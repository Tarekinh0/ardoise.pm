package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
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
const margeChiffrement = 1 + 1 + crypto.MaxDestinatairesMD*crypto.TailleEntreeMD + crypto.TailleNonce + 16

// margeRequete est la tolérance accordée à l'enveloppe JSON du dépôt.
const margeRequete = 4096

// maxDestinataires borne la liste « pour » d'un dépôt.
const maxDestinataires = 32

// delaiConstantOracle est le délai ajouté avant de retourner une erreur
// « non admis » (S2) pour uniformiser le temps de réponse avec celui
// d'une ardoise inexistante.
const delaiConstantOracle = 50 * time.Millisecond

// Throttling GET : limite de débit par IP (S1 + mesure compagnon CHIF-5).
const (
	requetesGETParMinute = 30
	fenetreGET           = time.Minute
)

// compteurGET suit le nombre de requêtes GET par IP.
type compteurGET struct {
	compteur int
	reinit   time.Time
}

// limiteurDebit implémente un token bucket simple par IP avec nettoyage.
type limiteurDebit struct {
	mu        sync.Mutex
	compteurs map[string]*compteurGET
}

// NouveauLimiteurDebit crée un limiteur de débit GET, avec une goroutine de
// nettoyage des compteurs expirés, liée au contexte fourni.
func NouveauLimiteurDebit(ctx context.Context) *limiteurDebit {
	l := &limiteurDebit{
		compteurs: make(map[string]*compteurGET),
	}
	go func() {
		ticker := time.NewTicker(fenetreGET)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				l.nettoyer()
			case <-ctx.Done():
				return
			}
		}
	}()
	return l
}

func (l *limiteurDebit) autoriser(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	maintenant := time.Now()
	c, existe := l.compteurs[ip]
	if !existe || maintenant.After(c.reinit) {
		l.compteurs[ip] = &compteurGET{compteur: 1, reinit: maintenant.Add(fenetreGET)}
		return true
	}
	if c.compteur >= requetesGETParMinute {
		return false
	}
	c.compteur++
	return true
}

// nettoyer supprime les compteurs expirés.
func (l *limiteurDebit) nettoyer() {
	l.mu.Lock()
	defer l.mu.Unlock()
	maintenant := time.Now()
	for ip, c := range l.compteurs {
		if maintenant.After(c.reinit) {
			delete(l.compteurs, ip)
		}
	}
}

func extensionBase64(n int64) int64 {
	return (n*4 + 2) / 3
}

// Dependances rassemble les collaborateurs optionnels du Handler.
type Dependances struct {
	Analyseur icap.Analyseur
	Journal   *journal.Journal
	Groupes   *Groupes
	Limiteur  *limiteurDebit // limiteur de débit GET (nil = pas de limite)
}

// depotInterne est la représentation intermédiaire d'un dépôt après
// décodage et validation de l'enveloppe HTTP.
type depotInterne struct {
	Contenu            []byte
	Duree              time.Duration
	LectureUnique      bool
	Pour               []string
	MarquageComplement string
	IDSuggere          string // CHIF-5 aveugle : identifiant serveur suggéré
	CleChiffrement     []byte // CHIF-5 analysé : clé fournie par le client
	BlobSalt           []byte // CHIF-5 analysé : sel HKDF fourni par le client
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
	errCollisionMots       = errors.New("collision sur l'identifiant dérivé des mots : veuillez réessayer avec « ardoise push --mots » (incident rarissime)")
)

// Handler construit le routeur de l'API versionnée.
func Handler(inst *config.Instance, magasin store.Magasin, jetons *Jetons, deps Dependances) http.Handler {
	politique := inst.Politique()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/politique", func(w http.ResponseWriter, r *http.Request) {
		ecrireJSON(w, http.StatusOK, politique)
	})
	mux.Handle("POST /v1/ardoises", exigerIdentite(inst, jetons, deps.Journal, deposerArdoise(inst, magasin, deps)))
	mux.Handle("GET /v1/ardoises/{id}", exigerIdentite(inst, jetons, deps.Journal, recupererArdoise(inst, magasin, deps)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&ecrivainErreursAPI{ResponseWriter: w}, r)
	})
}

// deposerArdoise traite POST /v1/ardoises.
func deposerArdoise(inst *config.Instance, magasin store.Magasin, deps Dependances) http.HandlerFunc {
	tailleMax := inst.Contenu.TailleMax
	analyse := inst.Mode == config.ModeAnalyse
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
			defer crypto.Effacer(contenu)
		}
		if int64(len(contenu)) > borneContenu {
			ecrireErreur(w, http.StatusRequestEntityTooLarge, "taille_depassee",
				fmt.Sprintf("le contenu dépasse la taille maximale de l'instance (%s)", inst.Contenu.TailleMaxTexte))
			return
		}

		// Validation cle_chiffrement / blob_salt (CHIF-5 analysé)
		var cleChiffrement, blobSalt []byte
		aCle := req.CleChiffrement != ""
		aBlob := req.BlobSalt != ""
		if aCle != aBlob {
			ecrireErreur(w, http.StatusBadRequest, "requete_invalide",
				"cle_chiffrement et blob_salt doivent être présents ensemble ou absents ensemble")
			return
		}
		if aCle {
			if !analyse {
				ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
					"cle_chiffrement refusée : le serveur ne reçoit pas de clé en mode aveugle")
				return
			}
			cleChiffrement, err = base64.StdEncoding.DecodeString(req.CleChiffrement)
			if err != nil || len(cleChiffrement) != crypto.TailleCle {
				ecrireErreur(w, http.StatusBadRequest, "requete_invalide",
					"cle_chiffrement invalide (attendu : 32 octets en base64)")
				return
			}
			blobSalt, err = base64.StdEncoding.DecodeString(req.BlobSalt)
			if err != nil || len(blobSalt) != crypto.TailleBlobSalt {
				crypto.Effacer(cleChiffrement)
				ecrireErreur(w, http.StatusBadRequest, "requete_invalide",
					"blob_salt invalide (attendu : 16 octets en base64)")
				return
			}
			defer crypto.Effacer(cleChiffrement)
		}

		// Validation id_suggere (CHIF-5 aveugle)
		if req.IDSuggere != "" {
			if analyse {
				ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
					"id_suggere refusé : le serveur dérive l'identifiant en mode analysé")
				return
			}
			if !crypto.IDServeurValide(req.IDSuggere) {
				ecrireErreur(w, http.StatusBadRequest, "requete_invalide",
					"id_suggere invalide (attendu : 12 caractères parmi a-z et 2-9)")
				return
			}
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
			lectureUnique = true
		case config.LectureUniqueInterdit:
			if req.LectureUnique {
				ecrireErreur(w, http.StatusUnprocessableEntity, "lecture_unique_refusee",
					"la destruction à la première lecture est interdite par la politique de l'instance")
				return
			}
		}

		if len(req.Pour) > 0 {
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
			IDSuggere:          req.IDSuggere,
			CleChiffrement:     cleChiffrement,
			BlobSalt:           blobSalt,
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
			case errors.Is(err, errCollisionMots):
				ecrireErreur(w, http.StatusConflict, "collision",
					"collision sur l'identifiant dérivé des mots : veuillez réessayer (incident rarissime)")
			case errors.Is(err, store.ErrSature):
				ecrireErreur(w, http.StatusServiceUnavailable, "service_sature",
					"l'instance a atteint le nombre maximal d'ardoises simultanées")
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
			reponse.Cle = base64.RawURLEncoding.EncodeToString(resultat.CleServeur)
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

// traiterDepot exécute le cœur du dépôt.
func traiterDepot(inst *config.Instance, magasin store.Magasin, analyseur icap.Analyseur, dep *depotInterne) (*resultatDepot, error) {
	analyse := inst.Mode == config.ModeAnalyse
	chiffre := dep.Contenu
	var cleServeur []byte
	chiffrementMots := len(dep.CleChiffrement) > 0

	if analyse {
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
		if chiffrementMots {
			// CHIF-5 analysé : chiffrer avec la clé fournie
			var err error
			chiffre, err = crypto.ChiffrerAvecCle(crypto.VersionMots, dep.BlobSalt, dep.CleChiffrement, dep.Contenu)
			if err != nil {
				return nil, err
			}
			// Pas de cleServeur : le client a déjà la clé
		} else {
			var err error
			chiffre, cleServeur, err = crypto.ChiffrerServeur(dep.Contenu)
			if err != nil {
				return nil, err
			}
		}
		crypto.Effacer(dep.Contenu)
	}

	echeance := time.Now().Add(dep.Duree)
	empreinte := crypto.Empreinte(chiffre)

	// CHIF-5 aveugle : l'ID est dérivé des mots par le client et
	// suggéré au serveur. Une seule tentative est effectuée car un
	// fallback vers un ID aléatoire briserait le lien mots→ID et
	// l'utilisateur perdrait définitivement son ardoise. La
	// probabilité de collision est de 1/34^12 ≈ 3.5×10^-19.
	if dep.IDSuggere != "" {
		err := magasin.Deposer(&store.Ardoise{
			ID:                 dep.IDSuggere,
			Chiffre:            chiffre,
			Empreinte:          empreinte,
			Echeance:           echeance,
			LectureUnique:      dep.LectureUnique,
			MarquageComplement: dep.MarquageComplement,
			Pour:               dep.Pour,
		})
		if err != nil {
			if errors.Is(err, store.ErrExiste) {
				return nil, errCollisionMots
			}
			return nil, err
		}
		return &resultatDepot{
			ID:         dep.IDSuggere,
			Empreinte:  empreinte,
			Echeance:   echeance,
			CleServeur: cleServeur,
		}, nil
	}

	var id string
	var err error
	for essai := 0; ; essai++ {
		if chiffrementMots && analyse {
			// CHIF-5 analysé : ID dérivé de la clé. La dérivation
			// est déterministe, donc un compteur la diversifie
			// pour éviter une collision sans issue.
			var sel []byte
			if essai > 0 {
				sel = []byte{byte(essai)}
			}
			id, err = crypto.DeriverIDDepuisCleAvecSel(dep.CleChiffrement, sel)
		} else {
			id, err = crypto.NouvelIDServeur()
		}
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
		// S1 : saturation du magasin
		if errors.Is(err, store.ErrSature) {
			return nil, err
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

// identiteJournal traduit l'identité de la requête vers sa forme journalisée.
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

// recupererArdoise traite GET /v1/ardoises/{id} avec throttling.
func recupererArdoise(inst *config.Instance, magasin store.Magasin, deps Dependances) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Throttling GET
		ip := ipClient(r)
		if deps.Limiteur != nil && !deps.Limiteur.autoriser(ip) {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", fenetreGET.Seconds()))
			ecrireErreur(w, http.StatusTooManyRequests, "trop_de_requetes",
				"limite de débit atteinte : veuillez réessayer plus tard")
			return
		}

		id := r.PathValue("id")
		if !crypto.IDServeurValide(id) {
			ecrireIntrouvable(w)
			return
		}
		identite, _ := IdentiteDepuisContexte(r.Context())
		utilisateur := ""
		if identite != nil {
			utilisateur = identite.Utilisateur
		}
		a, err := magasin.RecupererSi(id, func(a *store.Ardoise) bool {
			if len(a.Pour) == 0 {
				return true // ardoise au porteur
			}
			if utilisateur == "" {
				return false
			}
			if deps.Groupes == nil {
				// Pas de table de groupes : seules les identités
				// individuelles sont résolues (comparaison directe) ;
				// les groupes (« @... ») ne correspondent à personne.
				for _, d := range a.Pour {
					if len(d) > 0 && d[0] == '@' {
						continue
					}
					if d == utilisateur {
						return true
					}
				}
				return false
			}
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
				// S2 : délai constant avant réponse pour masquer
				// l'oracle temporel non-destinataire vs inexistant
				time.Sleep(delaiConstantOracle)
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

// ipClient extrait l'adresse IP du client depuis la requête.
// X-Forwarded-For n'est pas exploité : les connexions sont directes sur
// réseau d'administration (HE-1) et l'en-tête est falsifiable.
func ipClient(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
