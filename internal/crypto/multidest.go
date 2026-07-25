package crypto

// Chiffrement multi-destinataires « CHIF-MD » (docs/dat.md ADR-014, cas a) :
// la clé de contenu est enveloppée une fois par destinataire au moyen de sa
// clé publique X25519, chaque destinataire ouvrant seul avec son propre
// matériel. Bibliothèque standard exclusivement : crypto/ecdh (X25519),
// crypto/hkdf (HKDF-SHA256) et AES-256-GCM — aucune primitive absente de
// l'annexe B (SHA-256, AES-GCM) hormis X25519, introduit par ce schéma et
// documenté ici.
//
// # Format du chiffré (version 0x05)
//
//	0x05 ‖ n(1) ‖ n × entrée ‖ nonce(12) ‖ scellé AES-256-GCM(contenu, K)
//
//	entrée = empreinteIdentite(16) ‖ éphémère X25519 pub(32) ‖
//	         nonceEnveloppe(12) ‖ GCM_enveloppe(K)(48)
//
//   - n : nombre de destinataires (1..MaxDestinatairesMD) sur un octet ;
//   - empreinteIdentite : SHA-256 de l'identité du destinataire, tronquée à
//     16 octets — un index de recherche, pas un secret : elle permet au
//     destinataire de localiser son entrée sans essayer toutes les
//     enveloppes ;
//   - éphémère : clé publique X25519 générée pour CETTE entrée (une paire
//     éphémère par destinataire, jamais réutilisée) ;
//   - GCM_enveloppe(K) : la clé de contenu K (32 octets) scellée en
//     AES-256-GCM (32 + 16 d'étiquette = 48 octets) sous la clé
//     d'enveloppe :
//
//     cléEnveloppe = HKDF-SHA256(ECDH(éphémère, pub destinataire),
//     sel = éphémère pub, info = "ardoise.pm CHIF-MD v1")
//
// # Intégrité
//
// L'en-tête complet — octet de version, compteur et table des entrées —
// est couvert par les données additionnelles authentifiées (AAD) du GCM de
// contenu, scellé sous K : ajouter, retirer ou altérer une entrée (ou le
// compteur, ou la version) fait échouer l'ouverture du contenu chez tout
// destinataire légitime. Un attaquant sans K ne peut pas reconstruire
// l'étiquette du contenu pour une table modifiée ; un destinataire
// légitime détecte donc toute manipulation de la liste des destinataires.
// Chaque enveloppe est de surcroît scellée avec pour AAD la version et
// l'empreinte d'identité de son entrée : une enveloppe recopiée sous une
// autre identité ne s'ouvre pas.
//
// # Identifiant
//
// Le fragment d'identifiant ne porte AUCUNE clé : le matériel d'ouverture
// est la clé privée du destinataire, pas un secret transporté. L'identifiant
// prend la forme « <id-serveur>#md » : la sentinelle « md » indique au
// client qu'aucune clé symétrique n'est attendue — l'octet de version du
// chiffré reste seul autoritaire sur le schéma.

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// VersionMultiDest est l'octet de version du chiffré multi-destinataires.
const VersionMultiDest byte = 0x05

// SentinelleMultiDest est le fragment d'identifiant du schéma CHIF-MD :
// une sentinelle, jamais une clé (voir le commentaire de format).
const SentinelleMultiDest = "md"

// MaxDestinatairesMD borne le nombre d'entrées de la table (le compteur
// tient sur un octet ; la borne produit est plus stricte que 255 pour
// contenir la taille de l'en-tête).
const MaxDestinatairesMD = 64

// Dimensions du format CHIF-MD.
const (
	tailleEmpreinteIdentite = 16                                                                            // SHA-256 tronquée
	tailleClePubliqueMD     = 32                                                                            // X25519
	tailleEnveloppe         = TailleCle + 16                                                                // clé scellée + étiquette GCM
	TailleEntreeMD          = tailleEmpreinteIdentite + tailleClePubliqueMD + TailleNonce + tailleEnveloppe // 108
)

// infoCHIFMD lie la dérivation HKDF au produit et à la version du format.
const infoCHIFMD = "ardoise.pm CHIF-MD v1"

// DestinataireMD est un destinataire du chiffrement multi-destinataires :
// son identité (celle que l'instance authentifie) et sa clé publique X25519
// de l'annuaire de l'entité.
type DestinataireMD struct {
	Identite    string
	ClePublique []byte // 32 octets X25519
}

// EmpreinteIdentiteMD retourne l'empreinte d'identité du format CHIF-MD :
// SHA-256 de l'identité, tronquée à 16 octets.
func EmpreinteIdentiteMD(identite string) []byte {
	h := sha256.Sum256([]byte(identite))
	return h[:tailleEmpreinteIdentite]
}

// ChiffrerMultiDest chiffre selon CHIF-MD : une clé de contenu aléatoire à
// usage unique, enveloppée pour chaque destinataire sous sa clé publique
// X25519. Aucune clé n'est retournée : le matériel d'ouverture est la clé
// privée de chaque destinataire.
func ChiffrerMultiDest(clair []byte, destinataires []DestinataireMD) ([]byte, error) {
	if len(destinataires) == 0 {
		return nil, errors.New("CHIF-MD : aucun destinataire")
	}
	if len(destinataires) > MaxDestinatairesMD {
		return nil, fmt.Errorf("CHIF-MD : %d destinataires, %d au plus", len(destinataires), MaxDestinatairesMD)
	}

	courbe := ecdh.X25519()
	cle := make([]byte, TailleCle)
	if _, err := rand.Read(cle); err != nil {
		return nil, fmt.Errorf("génération de la clé de contenu : %w", err)
	}
	defer Effacer(cle)

	// En-tête : version ‖ compteur ‖ table des entrées.
	enTete := make([]byte, 0, 2+len(destinataires)*TailleEntreeMD)
	enTete = append(enTete, VersionMultiDest, byte(len(destinataires)))
	for _, d := range destinataires {
		pub, err := courbe.NewPublicKey(d.ClePublique)
		if err != nil {
			return nil, fmt.Errorf("clé publique du destinataire « %s » invalide : %w", d.Identite, err)
		}
		ephemere, err := courbe.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("génération de la clé éphémère : %w", err)
		}
		partage, err := ephemere.ECDH(pub)
		if err != nil {
			return nil, fmt.Errorf("accord de clé pour « %s » : %w", d.Identite, err)
		}
		ephemerePub := ephemere.PublicKey().Bytes()
		cleEnveloppe, err := hkdf.Key(sha256.New, partage, ephemerePub, infoCHIFMD, TailleCle)
		Effacer(partage)
		if err != nil {
			return nil, fmt.Errorf("dérivation de la clé d'enveloppe : %w", err)
		}
		empreinte := EmpreinteIdentiteMD(d.Identite)
		nonceEnveloppe := make([]byte, TailleNonce)
		if _, err := rand.Read(nonceEnveloppe); err != nil {
			Effacer(cleEnveloppe)
			return nil, fmt.Errorf("génération du nonce d'enveloppe : %w", err)
		}
		gcm, err := nouveauGCM(cleEnveloppe)
		if err != nil {
			Effacer(cleEnveloppe)
			return nil, err
		}
		// AAD de l'enveloppe : version et empreinte d'identité — une
		// enveloppe déplacée sous une autre entrée ne s'ouvre pas.
		aadEnveloppe := append([]byte{VersionMultiDest}, empreinte...)
		enveloppe := gcm.Seal(nil, nonceEnveloppe, cle, aadEnveloppe)
		Effacer(cleEnveloppe)

		enTete = append(enTete, empreinte...)
		enTete = append(enTete, ephemerePub...)
		enTete = append(enTete, nonceEnveloppe...)
		enTete = append(enTete, enveloppe...)
	}

	// Contenu : AES-256-GCM sous K, l'en-tête complet en AAD (voir le
	// commentaire de format).
	nonce := make([]byte, TailleNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("génération du nonce : %w", err)
	}
	gcm, err := nouveauGCM(cle)
	if err != nil {
		return nil, err
	}
	chiffre := make([]byte, 0, len(enTete)+len(nonce)+len(clair)+gcm.Overhead())
	chiffre = append(chiffre, enTete...)
	chiffre = append(chiffre, nonce...)
	return gcm.Seal(chiffre, nonce, clair, enTete), nil
}

// entreeMD est une entrée de la table des destinataires, découpée.
type entreeMD struct {
	empreinte      []byte
	ephemerePub    []byte
	nonceEnveloppe []byte
	enveloppe      []byte
}

// decouperMultiDest sépare un chiffré CHIF-MD en en-tête (AAD), entrées,
// nonce et corps scellé.
func decouperMultiDest(chiffre []byte) (enTete []byte, entrees []entreeMD, nonce, scelle []byte, err error) {
	if len(chiffre) < 2 || chiffre[0] != VersionMultiDest {
		return nil, nil, nil, nil, ErrDechiffrement
	}
	n := int(chiffre[1])
	if n == 0 || n > MaxDestinatairesMD {
		return nil, nil, nil, nil, ErrDechiffrement
	}
	finTable := 2 + n*TailleEntreeMD
	// Le corps scellé comporte au minimum l'étiquette GCM (16 octets).
	if len(chiffre) < finTable+TailleNonce+16 {
		return nil, nil, nil, nil, ErrDechiffrement
	}
	entrees = make([]entreeMD, 0, n)
	for i := 0; i < n; i++ {
		debut := 2 + i*TailleEntreeMD
		e := chiffre[debut : debut+TailleEntreeMD]
		entrees = append(entrees, entreeMD{
			empreinte:      e[:tailleEmpreinteIdentite],
			ephemerePub:    e[tailleEmpreinteIdentite : tailleEmpreinteIdentite+tailleClePubliqueMD],
			nonceEnveloppe: e[tailleEmpreinteIdentite+tailleClePubliqueMD : tailleEmpreinteIdentite+tailleClePubliqueMD+TailleNonce],
			enveloppe:      e[tailleEmpreinteIdentite+tailleClePubliqueMD+TailleNonce:],
		})
	}
	enTete = chiffre[:finTable]
	nonce = chiffre[finTable : finTable+TailleNonce]
	scelle = chiffre[finTable+TailleNonce:]
	return enTete, entrees, nonce, scelle, nil
}

// ouvrirEnveloppeMD tente d'ouvrir l'enveloppe d'une entrée avec la clé
// privée fournie. La clé de contenu retournée est à effacer par l'appelant.
func ouvrirEnveloppeMD(prive *ecdh.PrivateKey, e entreeMD) ([]byte, error) {
	courbe := ecdh.X25519()
	ephemerePub, err := courbe.NewPublicKey(e.ephemerePub)
	if err != nil {
		return nil, ErrDechiffrement
	}
	partage, err := prive.ECDH(ephemerePub)
	if err != nil {
		return nil, ErrDechiffrement
	}
	defer Effacer(partage)
	cleEnveloppe, err := hkdf.Key(sha256.New, partage, e.ephemerePub, infoCHIFMD, TailleCle)
	if err != nil {
		return nil, ErrDechiffrement
	}
	defer Effacer(cleEnveloppe)
	gcm, err := nouveauGCM(cleEnveloppe)
	if err != nil {
		return nil, ErrDechiffrement
	}
	aadEnveloppe := append([]byte{VersionMultiDest}, e.empreinte...)
	cle, err := gcm.Open(nil, e.nonceEnveloppe, e.enveloppe, aadEnveloppe)
	if err != nil {
		return nil, ErrDechiffrement
	}
	return cle, nil
}

// DechiffrerMultiDest ouvre un chiffré CHIF-MD avec la clé privée X25519
// du destinataire (32 octets). Si identite est renseignée, l'entrée est
// localisée par son empreinte d'identité ; sinon, chaque entrée est
// essayée — l'empreinte n'est qu'un index, la possession de la clé privée
// est ce qui ouvre réellement l'enveloppe.
func DechiffrerMultiDest(chiffre []byte, identite string, clePrivee []byte) ([]byte, error) {
	enTete, entrees, nonce, scelle, err := decouperMultiDest(chiffre)
	if err != nil {
		return nil, err
	}
	prive, err := ecdh.X25519().NewPrivateKey(clePrivee)
	if err != nil {
		return nil, errors.New("clé privée de destinataire absente ou de taille inattendue")
	}

	candidates := entrees
	if identite != "" {
		empreinte := EmpreinteIdentiteMD(identite)
		candidates = nil
		for _, e := range entrees {
			if subtle.ConstantTimeCompare(e.empreinte, empreinte) == 1 {
				candidates = append(candidates, e)
			}
		}
	}
	for _, e := range candidates {
		cle, err := ouvrirEnveloppeMD(prive, e)
		if err != nil {
			continue
		}
		gcm, errGCM := nouveauGCM(cle)
		Effacer(cle)
		if errGCM != nil {
			return nil, errGCM
		}
		clair, errOuverture := gcm.Open(nil, nonce, scelle, enTete)
		if errOuverture != nil {
			// L'enveloppe s'est ouverte mais pas le contenu : chiffré
			// altéré (table ou corps), aucune autre entrée n'y changera rien.
			return nil, ErrDechiffrement
		}
		return clair, nil
	}
	return nil, ErrDechiffrement
}

// GenererClePriveeMD produit une paire X25519 de destinataire : la clé
// privée (32 octets, à conserver en 0600 et effacer après usage) et la clé
// publique correspondante (32 octets, à publier dans l'annuaire).
func GenererClePriveeMD() (privee, publique []byte, err error) {
	paire, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("génération de la clé X25519 : %w", err)
	}
	return paire.Bytes(), paire.PublicKey().Bytes(), nil
}

// ClePubliqueMD dérive la clé publique X25519 d'une clé privée de
// destinataire (32 octets).
func ClePubliqueMD(clePrivee []byte) ([]byte, error) {
	prive, err := ecdh.X25519().NewPrivateKey(clePrivee)
	if err != nil {
		return nil, errors.New("clé privée de destinataire absente ou de taille inattendue")
	}
	return prive.PublicKey().Bytes(), nil
}
