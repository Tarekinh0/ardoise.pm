package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/icap"
	"ardoise.pm/internal/journal"
	"ardoise.pm/internal/store"
)

// margeChiffrement est la tolérance accordée au-delà de contenu.taille_max
// pour le surcoût du chiffrement client (en-tête de version, sel, nonce,
// étiquette GCM) : la borne s'applique au contenu, le serveur ne reçoit que
// du chiffré.
//
// Dans le pire cas — CHIF-MD avec MaxDestinatairesMD destinataires —
// le surcoût atteint 1 + 1 + MaxDestinatairesMD*TailleEntreeMD + TailleNonce + 16
// (≈ 7 Kio pour 64 destinataires). Cette constante unique couvre tous les
// schémas de chiffrement (CHIF-1/2/3/4 et CHIF-MD) sans discrimination.
const margeChiffrement = 1 + 1 + crypto.MaxDestinatairesMD*crypto.TailleEntreeMD + crypto.TailleNonce + 16

// margeRequete est la tolérance accordée à l'enveloppe JSON du dépôt
// (champs duree, lecture_unique, pour, marquage_complement et structure).
const margeRequete = 4096

// maxDestinataires borne la liste « pour » d'un dépôt : chaque entrée
// tient en 65 caractères au plus, la liste entière reste dans margeRequete.
const maxDestinataires = 32

// extensionBase64 retourne le nombre maximum d'octets après encodage base64
// standard d'une entrée de n octets. Le calcul est ceil(n * 4/3) — formulé
// sans flottant en (n*4+2)/3 — qui couvre l'expansion de la base64 sans
// tenir compte du padding dont le décodeur s'accommode.
//
// PR-108 : la garde contre le débordement (n > MaxInt64/4) a été retirée
// car le paramètre n est borné par la taille maximale de contenu validée au
// chargement de la configuration. Aucune valeur de n issue de config valide
// ne peut provoquer un débordement de l'arithmétique 64 bits.
func extensionBase64(n int64) int64 {
	return (n*4 + 2) / 3
}

// Dependances rassemble les collaborateurs optionnels du Handler : le
// client d'analyse ICAP (requis en mode analysé — son absence y vaut
// verdict indisponible, fail-closed), le journal d'imputabilité (nil :
// JOURN-4, aucune émission) et la table des groupes de destinataires
// (nil : aucun groupe résoluble, les groupes désignés ne correspondent à
// aucune identité).
type Dependances struct {
	Analyseur icap.Analyseur
	Journal   *journal.Journal
	Groupes   *Groupes
}

// depotInterne est la représentation intermédiaire d'un dépôt après
// décodage et validation de l'enveloppe HTTP (PR-103). Le contenu est
// le chiffré client en mode aveugle, le clair en mode analysé.
type depotInterne struct {
	Contenu            []byte
	Duree              time.Duration
	LectureUnique      bool
	Pour               []string
	MarquageComplement string
}

// resultatDepot rassemble les métadonnées issues d'un traiterDepot réussi.
type resultatDepot struct {
	ID         string
	Empreinte  string
	Echeance   time.Time
	CleServeur []byte // vide sauf mode analysé (CHIF-4)
}

var (
	errAnalyseDefavorable  = errors.New("verdict d'analyse défavorable")
	errAnalyseIndisponible = errors.New("verdict d'analyse indisponible")
)

// Handler construit le routeur de l'API versionnée, adossé au magasin. La
// politique est figée au démarrage : la configuration d'une instance ne
// change pas en cours d'exécution (ADR-002, artefact signé).
//
// jetons est la table AUTH-3, requise lorsque le mécanisme est « jeton »
// (chargée par Nouveau depuis auth.jetons), sans objet sinon.
//
// Le dépôt et la récupération sont derrière le contrôle d'authentification
// (ADR-009, voir exigerIdentite) ; GET /v1/politique est servi à tout client
// TLS avant rattachement d'identité, pour la raison documentée sur
// exigerIdentite. Aucune route ne liste ni ne recherche les ardoises
// (ADR-007).
func Handler(inst *config.Instance, magasin store.Magasin, jetons *Jetons, deps Dependances) http.Handler {
	politique := inst.Politique()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/politique", func(w http.ResponseWriter, r *http.Request) {
		ecrireJSON(w, http.StatusOK, politique)
	})
	mux.Handle("POST /v1/ardoises", exigerIdentite(inst, jetons, deps.Journal, deposerArdoise(inst, magasin, deps)))
	mux.Handle("GET /v1/ardoises/{id}", exigerIdentite(inst, jetons, deps.Journal, recupererArdoise(inst, magasin, deps)))
	// Les réponses par défaut du routeur (404 route inconnue, 405 méthode
	// refusée) sont réécrites dans la forme d'erreur JSON de l'API ; le
	// routeur conserve la sémantique HTTP (dont l'en-tête Allow du 405).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&ecrivainErreursAPI{ResponseWriter: w}, r)
	})
}

// deposerArdoise traite POST /v1/ardoises : bornes de taille (413), durée
// (422), régime de lecture unique (422), puis conservation du chiffré.
//
// En mode analysé (ADR-004, CHIF-4), le corps porte le CLAIR (base64) :
// après les contrôles, il est soumis à la chaîne d'analyse ICAP ; sur
// verdict favorable, le serveur chiffre sous une clé aléatoire à usage
// unique, remise à l'émetteur dans la réponse puis effacée. Sur tout autre
// verdict, refus 451 sans conservation (fail-closed, ADR-011).
//
// FENÊTRE EN CLAIR BORNÉE (docs/dat.md A.3-1) : en mode analysé, le clair
// et la clé n'existent qu'en mémoire, le temps de la requête — jamais
// écrits sur un support, jamais journalisés, jamais reproduits dans une
// erreur. Le tampon de clair est effacé sitôt le chiffrement accompli (et,
// par sûreté, en fin de requête), la clé sitôt la réponse sérialisée. La
// chaîne base64 du corps JSON, immuable en Go, relève de la limite
// documentée du ramasse-miettes (A.3-2).
func deposerArdoise(inst *config.Instance, magasin store.Magasin, deps Dependances) http.HandlerFunc {
	tailleMax := inst.Contenu.TailleMax
	analyse := inst.Mode == config.ModeAnalyse
	// Borne du corps HTTP : le contenu admissible — chiffré client avec son
	// surcoût en mode aveugle, clair en mode analysé — gonflé par base64
	// (4/3), plus l'enveloppe JSON. La division par excès (ceil) évite la
	// troncature des derniers octets (PR-005).
	borneContenu := tailleMax
	if !analyse {
		borneContenu += margeChiffrement
	}
	limiteCorps := extensionBase64(borneContenu) + margeRequete
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limiteCorps)
		var req requeteDepot
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var trop *http.MaxBytesError
			if errors.As(err, &trop) {
				ecrireErreur(w, http.StatusRequestEntityTooLarge, "taille_depassee",
					fmt.Sprintf("le contenu dépasse la taille maximale de l'instance (%s)", inst.Contenu.TailleMaxTexte))
				return
			}
			ecrireErreur(w, http.StatusBadRequest, "requete_invalide", "corps de dépôt illisible")
			return
		}

		contenu, err := base64.StdEncoding.DecodeString(req.Contenu)
		if err != nil || len(contenu) == 0 {
			ecrireErreur(w, http.StatusBadRequest, "requete_invalide", "contenu absent ou base64 invalide")
			return
		}
		if analyse {
			// Le tampon décodé est du clair : effacement garanti en fin de
			// requête, quel que soit le chemin de sortie.
			defer crypto.Effacer(contenu)
		}
		if int64(len(contenu)) > borneContenu {
			ecrireErreur(w, http.StatusRequestEntityTooLarge, "taille_depassee",
				fmt.Sprintf("le contenu dépasse la taille maximale de l'instance (%s)", inst.Contenu.TailleMaxTexte))
			return
		}

		duree := inst.Retention.DureeDefaut
		if req.Duree != "" {
			duree, err = config.ParseDuree(req.Duree)
			if err != nil {
				ecrireErreur(w, http.StatusBadRequest, "requete_invalide", "durée illisible")
				return
			}
			if duree > inst.Retention.DureeMax {
				ecrireErreur(w, http.StatusUnprocessableEntity, "duree_refusee",
					fmt.Sprintf("durée demandée au-delà de la borne de l'instance (%s)", config.FormatDuree(inst.Retention.DureeMax)))
				return
			}
		}

		lectureUnique := req.LectureUnique
		switch inst.Retention.LectureUnique {
		case config.LectureUniqueImposee:
			// RET-1 : la destruction à la première lecture est imposée par
			// l'instance, quel que soit le choix du client.
			lectureUnique = true
		case config.LectureUniqueInterdit:
			if req.LectureUnique {
				ecrireErreur(w, http.StatusUnprocessableEntity, "lecture_unique_refusee",
					"la destruction à la première lecture est interdite par la politique de l'instance")
				return
			}
		}

		if len(req.Pour) > 0 {
			// Sous identification déclarative, la désignation de
			// destinataires est structurellement refusée : l'identité du
			// lecteur, déclarée et falsifiable, ne peut fonder aucune
			// restriction de lecture (docs/man.md, « --pour »).
			if !inst.DestinatairesAdmissibles() {
				ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
					"la désignation de destinataires est refusée : l'identification déclarative ne permet pas de vérifier l'identité du lecteur")
				return
			}
			if len(req.Pour) > maxDestinataires {
				ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
					fmt.Sprintf("désignation de destinataires refusée : %d destinataires au plus", maxDestinataires))
				return
			}
			for _, destinataire := range req.Pour {
				if !DestinataireValide(destinataire) {
					// L'entrée fautive n'est pas reproduite : elle pourrait
					// contenir n'importe quoi.
					ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
						"désignation de destinataires refusée : entrée invalide (attendu : une identité « alice.durand » ou un groupe « @equipe-reseau »)")
					return
				}
			}
		}

		identite, _ := IdentiteDepuisContexte(r.Context())

		dep := &depotInterne{
			Contenu:            contenu,
			Duree:              duree,
			LectureUnique:      lectureUnique,
			Pour:               req.Pour,
			MarquageComplement: req.MarquageComplement,
		}
		resultat, err := traiterDepot(inst, magasin, deps.Analyseur, dep)
		if err != nil {
			switch {
			case errors.Is(err, errAnalyseDefavorable) || errors.Is(err, errAnalyseIndisponible):
				if deps.Journal != nil {
					deps.Journal.Consigner(journal.Entree{
						Evenement: journal.EvenementDepotRefuseAnalyse,
						Identite:  identiteJournal(identite),
					})
				}
				if errors.Is(err, errAnalyseDefavorable) {
					ecrireErreur(w, statutAnalyseRefusee, "analyse_defavorable",
						"dépôt refusé : la chaîne d'analyse de l'instance a rendu un verdict défavorable")
				} else {
					ecrireErreur(w, statutAnalyseRefusee, "analyse_indisponible",
						"dépôt refusé : aucun verdict d'analyse n'a pu être obtenu (fail-closed)")
				}
			default:
				ecrireErreurInterne(w)
			}
			return
		}

		reponse := reponseDepot{
			ID:        resultat.ID,
			Empreinte: resultat.Empreinte,
			Echeance:  resultat.Echeance.UTC().Format(time.RFC3339),
		}
		if len(resultat.CleServeur) > 0 {
			// La clé part vers l'émetteur, une seule fois ; elle n'existe
			// nulle part ailleurs — ni magasin, ni journal, ni erreur.
			//
			// Limitation documentée (docs/dat.md A.3-2, registre R-002) :
			// EncodeToString crée une copie string immuable de la clé,
			// qui ne peut pas être effacée avant le ramasse-miettes.
			reponse.Cle = base64.RawURLEncoding.EncodeToString(resultat.CleServeur)
			// PR-001 : effacement explicite de la clé serveur après
			// sérialisation — le []byte original ne survit pas à la
			// réponse. La copie string immuable de EncodeToString relève
			// de la limitation documentée A.3-2 (R-002).
			crypto.Effacer(resultat.CleServeur)
		}
		ecrireJSON(w, http.StatusCreated, reponse)
		if deps.Journal != nil {
			deps.Journal.Consigner(journal.Entree{
				Evenement: journal.EvenementDepot,
				Identite:  identiteJournal(identite),
				IDServeur: resultat.ID,
				Empreinte: resultat.Empreinte,
				Echeance:  resultat.Echeance.UTC().Format(time.RFC3339),
			})
		}
	}
}

// traiterDepot exécute le cœur du dépôt (PR-103) : analyse ICAP en mode
// analysé (ADR-004/ADR-011), chiffrement serveur (CHIF-4), conservation
// dans le magasin avec retry sur collision d'identifiant. En mode aveugle,
// le contenu est déjà chiffré (CHIF-1/2/3/MD) et conservé tel quel.
//
// La fonction ne manipule ni http.Request ni http.ResponseWriter : elle
// opère sur des données décodées et retourne une erreur que l'appelant
// traduit en réponse HTTP.
func traiterDepot(inst *config.Instance, magasin store.Magasin, analyseur icap.Analyseur, dep *depotInterne) (*resultatDepot, error) {
	analyse := inst.Mode == config.ModeAnalyse
	chiffre := dep.Contenu
	var cleServeur []byte

	if analyse {
		// ADR-004 : soumission synchrone bloquante, verdict avant toute
		// conservation. Un analyseur absent vaut indisponible : le
		// fail-closed ne se contourne pas, même par une erreur de
		// montage (ADR-011).
		verdict := icap.VerdictIndisponible
		if analyseur != nil {
			verdict = analyseur.Analyser(dep.Contenu)
		}
		if verdict != icap.VerdictFavorable {
			if verdict == icap.VerdictDefavorable {
				return nil, errAnalyseDefavorable
			}
			return nil, errAnalyseIndisponible
		}
		var err error
		chiffre, cleServeur, err = crypto.ChiffrerServeur(dep.Contenu)
		if err != nil {
			return nil, err
		}
		// La fenêtre en clair se referme ici : le clair est effacé dès
		// le chiffrement accompli, la clé dès la réponse écrite.
		crypto.Effacer(dep.Contenu)
	}

	echeance := time.Now().Add(dep.Duree)
	empreinte := crypto.Empreinte(chiffre)
	var id string
	var err error
	for essai := 0; ; essai++ {
		id, err = crypto.NouvelIDServeur()
		if err != nil {
			return nil, err
		}
		err = magasin.Deposer(&store.Ardoise{
			ID:                 id,
			Chiffre:            chiffre,
			Empreinte:          empreinte,
			Echeance:           echeance,
			LectureUnique:      dep.LectureUnique,
			MarquageComplement: dep.MarquageComplement,
			Pour:               dep.Pour,
		})
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrExiste) || essai >= 3 {
			return nil, err
		}
	}

	return &resultatDepot{
		ID:         id,
		Empreinte:  empreinte,
		Echeance:   echeance,
		CleServeur: cleServeur,
	}, nil
}

// identiteJournal traduit l'identité de la requête vers sa forme
// journalisée (ADR-005) : identité, mécanisme, et marque déclarative
// explicite sous AUTH-4.
func identiteJournal(id *Identite) *journal.Identite {
	if id == nil {
		return nil
	}
	return &journal.Identite{
		Utilisateur: id.Utilisateur,
		Hote:        id.Hote,
		Mecanisme:   id.Mecanisme,
		Declaratif:  id.Mecanisme == MecanismeDeclaratif,
	}
}

// recupererArdoise traite GET /v1/ardoises/{id}. La consommation d'une
// ardoise à lecture unique est atomique dans le magasin : le contenu n'est
// servi qu'à une seule requête, les suivantes reçoivent le code 5.
//
// Lorsque l'ardoise désigne des destinataires (« pour »), l'identité
// authentifiée du lecteur doit être désignée — directement ou par un
// groupe de la table auth.groupes. Un lecteur non désigné reçoit la MÊME
// réponse, octet pour octet, qu'une ardoise inexistante (ecrireIntrouvable,
// code 5) : rien ne lui apprend que l'ardoise existe — c'est ce qui rend
// « un identifiant obtenu par un tiers non désigné » inexploitable
// (docs/man.md, « --pour »). Le refus est évalué AVANT toute consommation
// (RecupererSi) : un tiers ne détruit jamais une ardoise à lecture unique.
// Seul le journal de l'instance distingue ce refus (métadonnées seules).
func recupererArdoise(inst *config.Instance, magasin store.Magasin, deps Dependances) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !crypto.IDServeurValide(id) {
			// Un identifiant malformé reçoit la même réponse qu'un
			// identifiant inconnu : rien n'est distinguable (code 5).
			ecrireIntrouvable(w)
			return
		}
		identite, _ := IdentiteDepuisContexte(r.Context())
		utilisateur := ""
		if identite != nil {
			utilisateur = identite.Utilisateur
		}
		a, err := magasin.RecupererSi(id, func(a *store.Ardoise) bool {
			return deps.Groupes.LecteurAdmis(a.Pour, utilisateur)
		})
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNonAdmis):
				if deps.Journal != nil {
					deps.Journal.Consigner(journal.Entree{
						Evenement: journal.EvenementLectureRefuseeDestinataire,
						Identite:  identiteJournal(identite),
						IDServeur: id,
					})
				}
				ecrireIntrouvable(w)
			case errors.Is(err, store.ErrIntrouvable):
				ecrireIntrouvable(w)
			default:
				ecrireErreurInterne(w)
			}
			return
		}
		ecrireJSON(w, http.StatusOK, reponseArdoise{
			Contenu:       base64.StdEncoding.EncodeToString(a.Chiffre),
			Empreinte:     a.Empreinte,
			Echeance:      a.Echeance.UTC().Format(time.RFC3339),
			LectureUnique: a.LectureUnique,
			Marquage: reponseMarquage{
				Actif:      inst.Marquage.Actif,
				Libelle:    inst.Marquage.Libelle,
				Complement: a.MarquageComplement,
			},
		})
		if deps.Journal != nil {
			deps.Journal.Consigner(journal.Entree{
				Evenement: journal.EvenementLecture,
				Identite:  identiteJournal(identite),
				IDServeur: a.ID,
				Empreinte: a.Empreinte,
				Echeance:  a.Echeance.UTC().Format(time.RFC3339),
			})
		}
	}
}
