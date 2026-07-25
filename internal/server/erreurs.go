package server

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"strings"
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

// statutAnalyseRefusee est le statut HTTP des refus d'analyse (docs/man.md :
// code de retour client 7) : 451, le code figurant dans le corps
// (« analyse_defavorable » ou « analyse_indisponible »).
const statutAnalyseRefusee = 451

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

// ecrireErreur émet une réponse d'erreur structurée (enveloppe JSON).
func ecrireErreur(w http.ResponseWriter, statut int, code, message string) {
	ecrireJSON(w, statut, enveloppeErreur{Erreur: erreurAPI{Code: code, Message: message}})
}

// ecrivainErreursAPI remplace le corps des réponses 404 et 405 émises par
// défaut par le routeur (en texte brut) par la forme d'erreur JSON de
// l'API. Les réponses des handlers applicatifs — déjà en JSON, dont le 404
// du code 5 — passent inchangées : ce sont eux qui portent la sémantique.
//
// Le statut d'interception est mémorisé dans WriteHeader et le corps JSON
// est écrit dans Write — WriteHeader ne doit pas écrire dans le corps, le
// contrat http.ResponseWriter le réserve à la première écriture (PR-106).
type ecrivainErreursAPI struct {
	http.ResponseWriter
	intercepte bool
	statut     int
}

func (e *ecrivainErreursAPI) WriteHeader(statut int) {
	if (statut != http.StatusNotFound && statut != http.StatusMethodNotAllowed) ||
		strings.HasPrefix(e.Header().Get("Content-Type"), "application/json") {
		e.ResponseWriter.WriteHeader(statut)
		return
	}
	e.intercepte = true
	e.statut = statut
	// Le corps JSON est écrit dans Write, pas ici : le contrat
	// http.ResponseWriter réserve la première écriture à Write.
}

func (e *ecrivainErreursAPI) Write(corps []byte) (int, error) {
	if e.intercepte {
		code, message := "introuvable", "ressource inconnue"
		if e.statut == http.StatusMethodNotAllowed {
			code, message = "methode_refusee", "méthode non autorisée pour cette ressource"
		}
		e.Header().Set("Content-Type", "application/json; charset=utf-8")
		e.ResponseWriter.WriteHeader(e.statut)
		// PR-002 : satisfaire le contrat io.Writer — Write doit retourner
		// un compte entre 0 et len(corps). Le corps JSON remplace le corps
		// texte par défaut du routeur, mais l'appelant (net/http) s'attend
		// à ce que len(corps) octets aient été consommés.
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(enveloppeErreur{Erreur: erreurAPI{Code: code, Message: message}}); err != nil {
			log.Printf("ardoise : erreur d'encodage JSON (réécriture d'erreur routeur) : %v", err)
			return 0, err
		}
		if _, writeErr := e.ResponseWriter.Write(buf.Bytes()); writeErr != nil {
			return 0, writeErr
		}
		return len(corps), nil
	}
	return e.ResponseWriter.Write(corps)
}
