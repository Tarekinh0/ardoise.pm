// Package crypto met en œuvre l'inventaire cryptographique d'ardoise.pm
// (docs/dat.md, annexe B) pour le mode aveugle : chiffrement authentifié
// AES-256-GCM, dérivation de clé Argon2id, identifiants, empreintes et
// hygiène mémoire.
//
// # Schémas de protection (docs/dat.md §5.4)
//
//   - CHIF-2 (« cle ») : clé aléatoire de 256 bits à usage unique, générée
//     par le client. La clé constitue le fragment de l'identifiant et ne
//     transite jamais vers le serveur.
//
//   - CHIF-4 (« serveur ») : clé aléatoire de 256 bits à usage unique,
//     générée par le serveur après verdict d'analyse favorable (mode analysé,
//     ADR-004). L'octet de version 0x04 consigne la provenance serveur du
//     chiffrement (cécité a posteriori). Le déchiffrement est identique à
//     CHIF-2.
//
//   - CHIF-5 (« mots ») : 5 mots mnémoniques BIP39 français (55 bits
//     d'entropie) étirés par Argon2id → graine 256 bits → HKDF(graine)
//     pour l'ID serveur et HKDF(graine, blob_salt) pour la clé AES-256.
//     Niveau R−, hors contexte réglementé. La diversification par blob_salt
//     évite de recalculer Argon2id au déchiffrement (une seule fois ~0,5s
//     au lieu de deux). Voir mots.go.
//
//   - CHIF-MD (« multi-destinataires ») : clé de contenu enveloppée sous
//     X25519 pour chaque destinataire (ADR-014, cas a). Voir multidest.go.
//
// # Format du chiffré
//
// Le chiffré est opaque pour le serveur ; sa structure n'est lue que par le
// client. L'octet de version encode le schéma employé, ce qui permet au
// client de récupération de savoir quel matériel demander :
//
//	CHIF-2 : version(0x01) ‖ nonce(12) ‖ scellé AES-256-GCM
//	CHIF-4 : version(0x04) ‖ nonce(12) ‖ scellé AES-256-GCM
//	CHIF-5 : version(0x06) ‖ blob_salt(16) ‖ nonce(12) ‖ scellé AES-256-GCM
//
// L'en-tête (version et sel) est couvert par les données additionnelles
// authentifiées (AAD) du GCM : toute altération de l'en-tête fait échouer le
// déchiffrement au même titre qu'une altération du corps. Le nonce de
// 96 bits provient de crypto/rand ; la clé étant à usage unique par ardoise,
// le risque de réutilisation de nonce est neutralisé par construction.
// Aucune compression n'est appliquée avant chiffrement (annexe B).
//
// # Hygiène mémoire
//
// Clés et mots de passe ne circulent qu'en []byte, jamais en string, et
// s'effacent explicitement via Effacer après usage. Aucun type de ce paquet
// n'expose de méthode String sur du matériel de clé. La limite du
// ramasse-miettes de Go est documentée et assumée (docs/dat.md A.3-2).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Tailles des matériels cryptographiques (docs/dat.md, annexe B).
const (
	TailleCle   = 32 // clé AES-256
	TailleNonce = 12 // nonce GCM de 96 bits
	TailleSel   = 16 // sel Argon2id de 128 bits
)

// Paramètres Argon2id imposés par l'annexe B : mémoire 64 Mio,
// 3 itérations, parallélisme 4.
const (
	Argon2Memoire      = 64 * 1024 // en Kio
	Argon2Iterations   = 3
	Argon2Parallelisme = 4
)

// Octets de version du chiffré : un par schéma de protection.
const (
	VersionCle     byte = 0x01 // CHIF-2
	VersionServeur byte = 0x04 // CHIF-4 — chiffré par le serveur après analyse
	VersionMots    byte = 0x06 // CHIF-5 — mots mnémoniques
	// VersionMultiDest (0x05, CHIF-MD) est déclarée dans multidest.go avec
	// son format propre (ADR-014, cas a).
	//
	// Les octets 0x02 (ex-CHIF-3) et 0x03 (ex-CHIF-1) sont retirés :
	// les schémas CHIF-1 et CHIF-3 ont été supprimés en faveur de CHIF-5
	// (5 mots mnémoniques). Tout chiffré portant ces versions est rejeté
	// comme « version inconnue ».
)

// ErrDechiffrement est l'unique erreur de déchiffrement : elle ne distingue
// jamais un mauvais matériel de clé d'un contenu altéré, le GCM ne le
// permettant pas et cette indistinction n'exposant aucun canal d'inférence.
var ErrDechiffrement = errors.New("déchiffrement impossible : matériel de clé incorrect ou contenu altéré")

// erreurInvalide est retournée par decouper lorsque le chiffré est trop
// court pour être découpé. Distincte de ErrDechiffrement pour éviter que
// l'appelant ne confonde un chiffré corrompu avec un chiffré vide.
var erreurInvalide = errors.New("chiffré invalide")

// Effacer met à zéro chaque tampon fourni. À appeler (au besoin en defer)
// sur tout matériel de clé et tout mot de passe dès qu'il cesse de servir.
// Best effort : le ramasse-miettes peut conserver des copies (A.3-2).
func Effacer(tampons ...[]byte) {
	for _, tampon := range tampons {
		for i := range tampon {
			tampon[i] = 0
		}
	}
}

// ChiffrerCle chiffre selon CHIF-2 : clé aléatoire à usage unique. La clé
// retournée est le matériel du fragment d'identifiant ; l'appelant l'efface
// après usage.
func ChiffrerCle(clair []byte) (chiffre, cle []byte, err error) {
	cle = make([]byte, TailleCle)
	if _, err := rand.Read(cle); err != nil {
		return nil, nil, fmt.Errorf("génération de la clé : %w", err)
	}
	chiffre, err = sceller(VersionCle, nil, cle, clair)
	if err != nil {
		Effacer(cle)
		return nil, nil, err
	}
	return chiffre, cle, nil
}

// ChiffrerServeur chiffre selon CHIF-4 (mode analysé) : même mécanique que
// CHIF-2 — clé aléatoire de 256 bits à usage unique — sous l'octet de
// version 0x04 qui consigne la provenance serveur du chiffrement (ADR-004,
// cécité a posteriori). La clé retournée est remise à l'émetteur dans la
// réponse de dépôt puis effacée par l'appelant : elle ne doit jamais être
// conservée ni journalisée côté serveur.
func ChiffrerServeur(clair []byte) (chiffre, cle []byte, err error) {
	cle = make([]byte, TailleCle)
	if _, err := rand.Read(cle); err != nil {
		return nil, nil, fmt.Errorf("génération de la clé : %w", err)
	}
	chiffre, err = sceller(VersionServeur, nil, cle, clair)
	if err != nil {
		Effacer(cle)
		return nil, nil, err
	}
	return chiffre, cle, nil
}

// Schema retourne l'octet de version du chiffré, qui encode le schéma de
// protection employé au dépôt. La vérification `len(chiffre) == 0` est
// défensive : tout chemin d'appel vérifie déjà la taille minimale (GCM
// exigeant 1 + nonce + tag), mais cette redondance protège contre un appel
// accidentel depuis un futur point d'entrée (PR-108 — laissée en place
// pour la robustesse, malgré une couverture de test marginale).
func Schema(chiffre []byte) (byte, error) {
	if len(chiffre) == 0 {
		return 0, errors.New("chiffré vide")
	}
	switch v := chiffre[0]; v {
	case VersionCle, VersionServeur, VersionMultiDest, VersionMots:
		return v, nil
	default:
		return 0, fmt.Errorf("version de chiffré inconnue (0x%02x)", v)
	}
}

// BesoinCle indique si le schéma exige le matériel de clé du fragment
// d'identifiant.
func BesoinCle(version byte) bool {
	return version == VersionCle || version == VersionServeur
}

// BesoinMots indique si le schéma exige des mots mnémoniques (CHIF-5).
func BesoinMots(version byte) bool {
	return version == VersionMots
}

// EstMultiDest indique si le chiffré relève du schéma multi-destinataires
// (CHIF-MD) : l'ouverture exige la clé privée X25519 du destinataire —
// jamais un fragment d'identifiant ni un mot de passe (multidest.go).
func EstMultiDest(version byte) bool {
	return version == VersionMultiDest
}

// Dechiffrer ouvre un chiffré quel que soit son schéma, avec le matériel
// fourni : cle est le matériel de clé (fragment d'identifiant ou clé dérivée
// des mots pour CHIF-5). Le clair est retourné intact ; toute altération ou
// tout matériel erroné produit ErrDechiffrement.
func Dechiffrer(chiffre, cle []byte) ([]byte, error) {
	version, err := Schema(chiffre)
	if err != nil {
		return nil, err
	}
	if EstMultiDest(version) {
		// Le format CHIF-MD porte sa propre table d'enveloppes : son
		// ouverture passe par DechiffrerMultiDest, avec la clé privée du
		// destinataire.
		return nil, errors.New("chiffré multi-destinataires : la clé privée de destinataire est requise (CHIF-MD)")
	}
	if BesoinCle(version) && len(cle) != TailleCle {
		return nil, errors.New("matériel de clé absent ou de taille inattendue")
	}

	enTete, _, nonce, scelle, err := decouper(chiffre)
	if err != nil {
		return nil, err
	}

	// Pour CHIF-2, CHIF-4, CHIF-5 : la clé AEAD est la clé fournie
	// directement (CHIF-2/4) ou la clé déjà dérivée par le client (CHIF-5).
	var cleAEAD []byte
	switch version {
	case VersionCle, VersionServeur, VersionMots:
		// cleAEAD est une copie ; l'appelant reste responsable d'effacer cle.
		cleAEAD = append([]byte(nil), cle...)
	default:
		return nil, fmt.Errorf("crypto : version %#x inconnue", version)
	}
	defer Effacer(cleAEAD)

	gcm, err := nouveauGCM(cleAEAD)
	if err != nil {
		return nil, err
	}
	clair, err := gcm.Open(nil, nonce, scelle, enTete)
	if err != nil {
		return nil, ErrDechiffrement
	}
	return clair, nil
}

// sceller chiffre le clair sous la clé AEAD donnée, avec un nonce frais de
// crypto/rand, et assemble le format documenté : version ‖ sel? ‖ nonce ‖
// scellé. L'en-tête (version et sel) est passé en AAD.
func sceller(version byte, sel, cleAEAD, clair []byte) ([]byte, error) {
	nonce := make([]byte, TailleNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("génération du nonce : %w", err)
	}
	return scellerAvecNonce(version, sel, nonce, cleAEAD, clair)
}

// scellerAvecNonce est le cœur déterministe de sceller, isolé pour que les
// tests puissent produire des vecteurs à nonce fixé. Ne jamais appeler avec
// un nonce qui ne provient pas de crypto/rand.
func scellerAvecNonce(version byte, sel, nonce, cleAEAD, clair []byte) ([]byte, error) {
	gcm, err := nouveauGCM(cleAEAD)
	if err != nil {
		return nil, err
	}
	enTete := append([]byte{version}, sel...)
	chiffre := make([]byte, 0, len(enTete)+len(nonce)+len(clair)+gcm.Overhead())
	chiffre = append(chiffre, enTete...)
	chiffre = append(chiffre, nonce...)
	return gcm.Seal(chiffre, nonce, clair, enTete), nil
}

// Decouper sépare un chiffré en en-tête (version ‖ sel), sel, nonce et
// corps scellé, selon le format du schéma.
func Decouper(chiffre []byte) (enTete, sel, nonce, scelle []byte, err error) {
	return decouper(chiffre)
}

// decouper sépare un chiffré en en-tête (version ‖ sel), sel, nonce et
// corps scellé, selon le format du schéma.
func decouper(chiffre []byte) (enTete, sel, nonce, scelle []byte, err error) {
	// Garde X1 : chiffré vide ne panique pas sur chiffre[0].
	if len(chiffre) < 1 {
		return nil, nil, nil, nil, erreurInvalide
	}
	version := chiffre[0]
	tailleSel := 0
	if version == VersionMots {
		tailleSel = TailleBlobSalt
	}
	debutNonce := 1 + tailleSel
	debutScelle := debutNonce + TailleNonce
	// Le corps scellé comporte au minimum l'étiquette GCM (16 octets).
	if len(chiffre) < debutScelle+16 {
		return nil, nil, nil, nil, ErrDechiffrement
	}
	enTete = chiffre[:debutNonce]
	sel = chiffre[1:debutNonce]
	nonce = chiffre[debutNonce:debutScelle]
	scelle = chiffre[debutScelle:]
	return enTete, sel, nonce, scelle, nil
}

func nouveauGCM(cleAEAD []byte) (cipher.AEAD, error) {
	bloc, err := aes.NewCipher(cleAEAD)
	if err != nil {
		return nil, fmt.Errorf("initialisation AES : %w", err)
	}
	gcm, err := cipher.NewGCM(bloc)
	if err != nil {
		return nil, fmt.Errorf("initialisation GCM : %w", err)
	}
	return gcm, nil
}
