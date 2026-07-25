package server

import (
	"encoding/json"
	"log"
	"net/http"
)

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

// ecrireJSON sérialise une réponse en JSON. L'erreur d'encodage est
// journalisée en diagnostic mais ne peut pas être remontée à l'appelant —
// l'en-tête Content-Type et le statut HTTP ont déjà été écrits avant
// l'appel à Encode. Le message de log ne reproduit jamais de contenu,
// de clé ou d'identifiant complet.
func ecrireJSON(w http.ResponseWriter, statut int, corps any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statut)
	if err := json.NewEncoder(w).Encode(corps); err != nil {
		log.Printf("ardoise : erreur d'encodage JSON (statut %d) : %v", statut, err)
	}
}
