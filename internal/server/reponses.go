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
	// IDSuggere est l'identifiant serveur suggéré par le client (CHIF-5
	// aveugle). En mode aveugle, le client dérive l'identifiant depuis les
	// mots mnémoniques et le transmet au serveur pour que l'ardoise soit
	// stockée sous l'identifiant attendu au get --mots. 12 caractères
	// [a-z2-9]. Optionnel : si absent, le serveur génère un ID aléatoire.
	IDSuggere string `json:"id_suggere,omitempty"`
	// CleChiffrement et BlobSalt sont fournis par le client en mode analysé
	// CHIF-5 (--mots). Les deux doivent être présents ensemble ou absents
	// ensemble. CleChiffrement est une clé AES-256 en base64 (32 octets).
	// BlobSalt est le sel HKDF en base64 (16 octets).
	CleChiffrement string `json:"cle_chiffrement,omitempty"`
	BlobSalt       string `json:"blob_salt,omitempty"`
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

// ecrireJSON sérialise une réponse en JSON. Le corps est sérialisé avec
// json.Marshal avant l'émission de l'en-tête Content-Type et du statut HTTP :
// en cas d'échec de sérialisation, le client reçoit une 500 et non une 2xx
// avec un corps JSON corrompu. Le message de log ne reproduit jamais de contenu,
// de clé ou d'identifiant complet.
func ecrireJSON(w http.ResponseWriter, statut int, corps any) {
	donnees, err := json.Marshal(corps)
	if err != nil {
		log.Printf("ardoise : erreur de sérialisation JSON : %v", err)
		ecrireErreurInterne(w)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statut)
	if _, err := w.Write(donnees); err != nil {
		log.Printf("ardoise : erreur d'écriture de la réponse JSON (statut %d) : %v", statut, err)
	}
}
