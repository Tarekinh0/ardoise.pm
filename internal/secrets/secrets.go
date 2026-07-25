// Package secrets porte la détection locale de secrets du mode aveugle
// (ANA-3, docs/dat.md §5.5) : avant tout chiffrement et tout envoi, le
// contenu à déposer est balayé à la recherche d'authentifiants — clés
// privées PEM, jetons JWT, clés d'API à préfixe connu, chaînes à forte
// entropie en contexte de secret. La détection est une aide, pas une
// garantie (docs/man.md, SÉCURITÉ) ; elle est purement locale : aucun
// réseau, aucun fichier, aucune persistance.
//
// # Provenance — adapté de Qindu, internal/pii
//
// Le moteur (engine, recognizer, entity, overlap, entropy) et les
// détecteurs sont adaptés du paquet internal/pii du projet Qindu
// (/home/tarek/tools/qindu), d'origine AGPL-3.0. La reprise dans
// ardoise.pm est approuvée par le titulaire des droits ; le pont de
// licence (extraction en bibliothèque autonome sous double licence,
// ADR-012) est suivi au registre des risques sous R-006.
//
// # Sous-ensemble retenu
//
// Seuls les détecteurs d'AUTHENTIFIANTS sont repris : clés privées
// (privatekey), JWT (jwt), préfixes de secrets connus (secret_prefix) et
// secrets à entropie (secret_entropy), avec l'infrastructure qu'ils
// exigent. Les détecteurs de données personnelles de Qindu (creditcard,
// email, iban, phone, name_email) sont volontairement écartés : l'exigence
// d'ardoise (ES-12, R35) vise le dépôt d'authentifiants dans un service
// non prévu à cet effet, pas la détection de données personnelles.
//
// # Restitution expurgée
//
// L'API publique — Detecter — ne restitue JAMAIS le secret détecté : une
// alerte qui reproduirait sa découverte créerait la fuite qu'elle prétend
// prévenir. Chaque Detection porte le type, la ligne et un extrait réduit
// aux quatre premiers caractères suivis de « … ».
package secrets

import (
	"strings"
)

// Types de détection restitués par Detecter, en vocabulaire produit.
const (
	TypeClePrivee = "cle-privee" // bloc PEM/OpenSSH/PGP de clé privée
	TypeJWT       = "jwt"        // jeton JWT structurel
	TypeSecret    = "secret"     // clé d'API à préfixe connu ou chaîne à entropie
)

// tailleExtrait est le nombre de caractères du secret restitués dans
// l'extrait expurgé — assez pour situer, jamais assez pour exploiter.
const tailleExtrait = 4

// Detection est une alerte expurgée : le type de secret, la ligne du
// contenu (à partir de 1) et un extrait réduit. Le secret lui-même ne
// figure nulle part.
type Detection struct {
	Type    string // TypeClePrivee, TypeJWT ou TypeSecret
	Ligne   int    // ligne du début de la détection, à partir de 1
	Extrait string // quatre premiers caractères + « … », jamais plus
}

// Detecter balaie un contenu et retourne les détections d'authentifiants,
// triées par position, expurgées. Un contenu sans détection retourne nil.
func Detecter(contenu []byte) []Detection {
	if len(contenu) == 0 {
		return nil
	}
	// A.3-2 (limitation documentée, registre R-002) : string(contenu)
	// crée une copie immuable de l'intégralité du contenu en clair, qui
	// peut contenir des authentifiants (c'est l'objet de la détection).
	// Cette copie survit à crypto.Effacer(clair) chez l'appelant et ne
	// peut pas être effacée avant le ramasse-miettes. La conversion est
	// nécessaire au moteur de détection (interface string), mais la
	// fenêtre d'exposition est bornée à la durée de Detecter.
	texte := string(contenu)
	moteur := NewEngine(len(texte),
		NewPrivateKeyRecognizer(),
		NewJWTRecognizer(),
		NewSecretPrefixRecognizer(),
		NewSecretEntropyRecognizer(),
	)
	entites, err := moteur.Detect(texte)
	if err != nil {
		// La borne de taille du moteur est fixée à la taille du contenu :
		// aucune erreur n'est atteignable ; par prudence, aucune détection
		// plutôt qu'une panique.
		return nil
	}
	if len(entites) == 0 {
		return nil
	}
	detections := make([]Detection, 0, len(entites))
	for _, e := range entites {
		detections = append(detections, Detection{
			Type:    typeProduit(e.Type),
			Ligne:   1 + strings.Count(texte[:e.Start], "\n"),
			Extrait: expurger(e.Value),
		})
	}
	return detections
}

// typeProduit traduit un type d'entité du moteur vendu vers le vocabulaire
// produit.
func typeProduit(t EntityType) string {
	switch t {
	case PrivateKey:
		return TypeClePrivee
	case JWT:
		return TypeJWT
	default:
		return TypeSecret
	}
}

// expurger réduit une valeur détectée à ses premiers caractères suivis de
// « … » : l'alerte situe le secret, elle ne le reproduit jamais.
func expurger(valeur string) string {
	if len(valeur) <= tailleExtrait {
		return valeur[:min(len(valeur), tailleExtrait)] + "…"
	}
	return valeur[:tailleExtrait] + "…"
}
