package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/icap"
	"ardoise.pm/internal/journal"
	"ardoise.pm/internal/store"
)

// erreurAPI est la forme unique des erreurs de l'API versionnée. Aucun
// message ne mentionne jamais un contenu, une clé ou un identifiant complet.
type erreurAPI struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type enveloppeErreur struct {
	Erreur erreurAPI `json:"erreur"`
}

// margeChiffrement est la tolérance accordée au-delà de contenu.taille_max
// pour le surcoût du chiffrement client (en-tête de version, sel, nonce,
// étiquette GCM) : la borne s'applique au contenu, le serveur ne reçoit que
// du chiffré.
const margeChiffrement = 512

// margeRequete est la tolérance accordée à l'enveloppe JSON du dépôt
// (champs duree, lecture_unique, pour, marquage_complement et structure).
const margeRequete = 4096

// requeteDepot est le corps de POST /v1/ardoises. En mode aveugle, contenu
// est le chiffré client, opaque, en base64 standard : le serveur ne fait
// aucune hypothèse sur sa structure et ne cherche jamais à l'interpréter.
type requeteDepot struct {
	Contenu            string   `json:"contenu"`
	Duree              string   `json:"duree,omitempty"`
	LectureUnique      bool     `json:"lecture_unique,omitempty"`
	Pour               []string `json:"pour,omitempty"`
	MarquageComplement string   `json:"marquage_complement,omitempty"`
}

// reponseDepot est la réponse de POST /v1/ardoises. Cle n'est renseignée
// qu'en mode analysé (CHIF-4) : la clé générée par le serveur après verdict
// favorable, remise à l'émetteur UNE SEULE FOIS puis effacée — jamais
// conservée, jamais journalisée (ADR-004, cécité a posteriori).
type reponseDepot struct {
	ID        string `json:"id"`
	Empreinte string `json:"empreinte"`
	Echeance  string `json:"echeance"`
	Cle       string `json:"cle,omitempty"` // base64url brut, mode analysé seulement
}

// reponseArdoise est la réponse de GET /v1/ardoises/{id}. Les champs de
// marquage sont restitués pour que le client applique le marquage en tête
// du contenu déchiffré (MARQ-1) — le serveur, aveugle, ne peut pas le faire
// lui-même ; leur exploitation par le client arrive avec internal/marquage.
type reponseArdoise struct {
	Contenu       string          `json:"contenu"`
	Empreinte     string          `json:"empreinte"`
	Echeance      string          `json:"echeance"`
	LectureUnique bool            `json:"lecture_unique"`
	Marquage      reponseMarquage `json:"marquage"`
}

type reponseMarquage struct {
	Actif      bool   `json:"actif"`
	Libelle    string `json:"libelle,omitempty"`
	Complement string `json:"complement,omitempty"`
}

// Dependances rassemble les collaborateurs optionnels du Handler : le
// client d'analyse ICAP (requis en mode analysé — son absence y vaut
// verdict indisponible, fail-closed) et le journal d'imputabilité (nil :
// JOURN-4, aucune émission).
type Dependances struct {
	Analyseur icap.Analyseur
	Journal   *journal.Journal
}

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
	mux.Handle("GET /v1/ardoises/{id}", exigerIdentite(inst, jetons, deps.Journal, recupererArdoise(inst, magasin, deps.Journal)))
	// Les réponses par défaut du routeur (404 route inconnue, 405 méthode
	// refusée) sont réécrites dans la forme d'erreur JSON de l'API ; le
	// routeur conserve la sémantique HTTP (dont l'en-tête Allow du 405).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&ecrivainErreursAPI{ResponseWriter: w}, r)
	})
}

// deposerArdoise traite POST /v1/ardoises : bornes de taille (413), durée
// (422), régime de lecture unique (422), puis conservation du chiffré.
func deposerArdoise(inst *config.Instance, magasin store.Magasin) http.HandlerFunc {
	tailleMax := inst.Contenu.TailleMax
	// Borne du corps HTTP : le chiffré admissible, gonflé par base64 (4/3),
	// plus l'enveloppe JSON.
	limiteCorps := (tailleMax+margeChiffrement)*4/3 + margeRequete
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

		chiffre, err := base64.StdEncoding.DecodeString(req.Contenu)
		if err != nil || len(chiffre) == 0 {
			ecrireErreur(w, http.StatusBadRequest, "requete_invalide", "contenu absent ou base64 invalide")
			return
		}
		if int64(len(chiffre)) > tailleMax+margeChiffrement {
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
			// destinataires restera refusée même lorsque « pour » sera pris
			// en charge (ARDOISE-0005) : l'identité du lecteur, déclarée et
			// falsifiable, ne peut fonder aucune restriction de lecture
			// (docs/man.md, « --pour »).
			if !inst.DestinatairesAdmissibles() {
				ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
					"la désignation de destinataires est refusée : l'identification déclarative ne permet pas de vérifier l'identité du lecteur")
				return
			}
			ecrireErreur(w, http.StatusUnprocessableEntity, "option_refusee",
				"la désignation de destinataires n'est pas disponible dans cette version")
			return
		}

		echeance := time.Now().Add(duree)
		empreinte := crypto.Empreinte(chiffre)
		var id string
		for essai := 0; ; essai++ {
			id, err = crypto.NouvelIDServeur()
			if err != nil {
				ecrireErreurInterne(w)
				return
			}
			err = magasin.Deposer(&store.Ardoise{
				ID:                 id,
				Chiffre:            chiffre,
				Empreinte:          empreinte,
				Echeance:           echeance,
				LectureUnique:      lectureUnique,
				MarquageComplement: req.MarquageComplement,
			})
			if err == nil {
				break
			}
			if !errors.Is(err, store.ErrExiste) || essai >= 3 {
				ecrireErreurInterne(w)
				return
			}
		}

		ecrireJSON(w, http.StatusCreated, reponseDepot{
			ID:        id,
			Empreinte: empreinte,
			Echeance:  echeance.UTC().Format(time.RFC3339),
		})
	}
}

// recupererArdoise traite GET /v1/ardoises/{id}. La consommation d'une
// ardoise à lecture unique est atomique dans le magasin : le contenu n'est
// servi qu'à une seule requête, les suivantes reçoivent le code 5.
func recupererArdoise(inst *config.Instance, magasin store.Magasin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !crypto.IDServeurValide(id) {
			// Un identifiant malformé reçoit la même réponse qu'un
			// identifiant inconnu : rien n'est distinguable (code 5).
			ecrireIntrouvable(w)
			return
		}
		a, err := magasin.Recuperer(id)
		if err != nil {
			if errors.Is(err, store.ErrIntrouvable) {
				ecrireIntrouvable(w)
			} else {
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
	}
}

// ecrireIntrouvable émet l'unique réponse du code 5 : une ardoise absente,
// expirée ou déjà consommée reçoit exactement les mêmes statut, code et
// message, afin de priver un tiers d'un moyen d'inférence (docs/man.md).
func ecrireIntrouvable(w http.ResponseWriter) {
	ecrireErreur(w, http.StatusNotFound, "introuvable", "ardoise inexistante, expirée ou déjà consommée")
}

// ecrireErreurInterne émet une erreur 500 sans aucun détail : rien de ce
// qui a échoué côté serveur ne doit transparaître.
func ecrireErreurInterne(w http.ResponseWriter) {
	ecrireErreur(w, http.StatusInternalServerError, "interne", "erreur interne de l'instance")
}

// ecrivainErreursAPI remplace le corps des réponses 404 et 405 émises par
// défaut par le routeur (en texte brut) par la forme d'erreur JSON de
// l'API. Les réponses des handlers applicatifs — déjà en JSON, dont le 404
// du code 5 — passent inchangées : ce sont eux qui portent la sémantique.
type ecrivainErreursAPI struct {
	http.ResponseWriter
	intercepte bool
}

func (e *ecrivainErreursAPI) WriteHeader(statut int) {
	if (statut != http.StatusNotFound && statut != http.StatusMethodNotAllowed) ||
		strings.HasPrefix(e.Header().Get("Content-Type"), "application/json") {
		e.ResponseWriter.WriteHeader(statut)
		return
	}
	e.intercepte = true
	code, message := "introuvable", "ressource inconnue"
	if statut == http.StatusMethodNotAllowed {
		code, message = "methode_refusee", "méthode non autorisée pour cette ressource"
	}
	e.Header().Set("Content-Type", "application/json; charset=utf-8")
	e.ResponseWriter.WriteHeader(statut)
	_ = json.NewEncoder(e.ResponseWriter).Encode(enveloppeErreur{Erreur: erreurAPI{Code: code, Message: message}})
}

func (e *ecrivainErreursAPI) Write(corps []byte) (int, error) {
	if e.intercepte {
		// Le corps par défaut du routeur est remplacé par le JSON ci-dessus.
		return len(corps), nil
	}
	return e.ResponseWriter.Write(corps)
}

func ecrireJSON(w http.ResponseWriter, statut int, corps any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statut)
	_ = json.NewEncoder(w).Encode(corps)
}

func ecrireErreur(w http.ResponseWriter, statut int, code, message string) {
	ecrireJSON(w, statut, enveloppeErreur{Erreur: erreurAPI{Code: code, Message: message}})
}
