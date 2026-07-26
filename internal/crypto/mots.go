// Package crypto — extension CHIF-5 (mots mnémoniques)
//
// Schéma : 5 mots BIP39 français → Argon2id → graine 256 bits
//
//	→ HKDF(graine) → ID serveur 12 caractères [a-z2-9]
//	→ HKDF(graine, blob_salt) → clé AES-256
//
// Le sel Argon2id est fixe : la diversification par blob se fait
// en aval via HKDF avec blob_salt. Ainsi Argon2id n'est appelé
// qu'une seule fois au get (~0,5s) et HKDF (microsecondes) assure
// que deux ardoises avec les mêmes mots ont des clés différentes.
package crypto

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// TailleBlobSalt est la longueur du sel HKDF stocké dans l'en-tête
// du chiffré CHIF-5. Il diversifie la clé par blob sans recalculer
// Argon2id.
const TailleBlobSalt = 16

// InfoIDMots et InfoCleMots sont les étiquettes de domaine HKDF
// pour la dérivation d'ID et de clé depuis la graine.
const (
	infoIDMots  = "ardoise.pm/mots/id/v1"
	infoCleMots = "ardoise.pm/mots/chiffre/v1"
)

// selMots est le sel fixe de l'étape Argon2id. Il n'a pas besoin
// d'être secret (RFC 9106 §4). Il est fixe pour que les mêmes mots
// produisent toujours la même graine.
const selMots = "ardoise.pm/mots/v1"

// GenererMots produit n mots aléatoires depuis la liste BIP39
// française. Chaque mot encode 11 bits d'entropie. n est
// typiquement 5 (55 bits).
func GenererMots(n int) ([]string, error) {
	if n < 1 || n > 8 {
		return nil, fmt.Errorf("nombre de mots %d invalide", n)
	}
	// Tirer assez d'octets pour n groupes de 11 bits.
	bits := n * 11
	octets := (bits + 7) / 8
	tampon := make([]byte, octets)
	if _, err := rand.Read(tampon); err != nil {
		return nil, fmt.Errorf("génération des mots : %w", err)
	}
	// Convertir en grande valeur pour extraire les groupes de 11 bits.
	var accum uint64
	dispo := 0
	mots := make([]string, 0, n)
	for i := 0; i < len(tampon); i++ {
		accum |= uint64(tampon[i]) << dispo
		dispo += 8
		for dispo >= 11 && len(mots) < n {
			index := accum & 0x7FF // 11 bits
			accum >>= 11
			dispo -= 11
			mots = append(mots, ListeBIP39[index])
		}
	}
	if len(mots) < n {
		return nil, errors.New("échec inattendu de la génération de mots")
	}
	return mots, nil
}

// MotsValides vérifie que chaque élément est présent dans la
// liste BIP39 française.
func MotsValides(mots []string) bool {
	if len(mots) == 0 {
		return false
	}
	for _, m := range mots {
		if !estDansListeBIP39(m) {
			return false
		}
	}
	return true
}

// estDansListeBIP39 vérifie l'appartenance par recherche binaire
// dans la liste triée.
func estDansListeBIP39(mot string) bool {
	gauche, droite := 0, len(ListeBIP39)-1
	for gauche <= droite {
		milieu := gauche + (droite-gauche)/2
		if ListeBIP39[milieu] == mot {
			return true
		}
		if ListeBIP39[milieu] < mot {
			gauche = milieu + 1
		} else {
			droite = milieu - 1
		}
	}
	return false
}

// DeriverGraine applique Argon2id à la concaténation des mots
// (séparés par des tirets) avec le sel fixe selMots.
// Retourne une graine de 32 octets.
func DeriverGraine(mots []string) []byte {
	password := strings.Join(mots, "-")
	return argon2.IDKey(
		[]byte(password),
		[]byte(selMots),
		Argon2Iterations,
		Argon2Memoire,
		Argon2Parallelisme,
		TailleCle,
	)
}

// DeriverIDDepuisGraine dérive l'identifiant serveur (12
// caractères [a-z2-9]) depuis la graine Argon2id via HKDF-SHA256
// avec étiquette infoIDMots, puis encodage dans l'alphabet de
// l'identifiant serveur.
func DeriverIDDepuisGraine(graine []byte) (string, error) {
	derivee, err := hkdf.Key(sha256.New, graine, nil, infoIDMots, TailleCle)
	if err != nil {
		return "", fmt.Errorf("dérivation de l'ID : %w", err)
	}
	return encoderID(derivee)
}

// DeriverIDDepuisCle dérive l'identifiant serveur directement
// depuis une clé AES-256. Utilisé par le serveur en mode analysé
// lorsque le client fournit cle_chiffrement.
// La clé fait office de graine pour le HKDF.
func DeriverIDDepuisCle(cle []byte) (string, error) {
	return DeriverIDDepuisCleAvecSel(cle, nil)
}

// DeriverIDDepuisCleAvecSel dérive l'identifiant serveur depuis une clé
// AES-256 et un sel de diversification. Le sel permet de varier l'ID
// lorsque le même matériel de clé produit une collision dans le magasin
// (mode analysé CHIF-5). Pour sel=nil, le comportement est identique à
// DeriverIDDepuisCle.
func DeriverIDDepuisCleAvecSel(cle, sel []byte) (string, error) {
	derivee, err := hkdf.Key(sha256.New, cle, sel, infoIDMots, TailleCle)
	if err != nil {
		return "", fmt.Errorf("dérivation de l'ID : %w", err)
	}
	return encoderID(derivee)
}

// DeriverCleDepuisGraine dérive la clé AES-256 depuis la graine
// Argon2id et le blob_salt. HKDF-SHA256 avec étiquette infoCleMots.
func DeriverCleDepuisGraine(graine, blobSalt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, graine, blobSalt, infoCleMots, TailleCle)
}

// encoderID transforme 32 octets en 12 caractères de l'alphabet
// [a-z2-9] via un PRNG déterministe (HMAC-DRBG) et échantillonnage
// avec rejet. Même logique que NouvelIDServeur mais déterministe.
func encoderID(derivee []byte) (string, error) {
	lecteur := nouveauPRNGDeterministe(derivee)
	return encoderIDDepuisSource(lecteur)
}

// nouveauPRNGDeterministe construit un lecteur d'octets déterministe
// amorcé par une graine. Implémentation simplifiée de PRNG par
// HMAC-SHA256. Ne suit PAS SP 800-90A.
//
// Cette implémentation est simplifiée et ne suit pas strictement
// SP 800-90A. Le compteur de réapprovisionnement est dérivé de la
// longueur du tampon (len(d.buf)/sha256.Size) plutôt que d'un compteur
// monotone indépendant, et le reseed prédictif n'est pas implémenté.
// Elle garantit l'uniformité de la distribution — sa seule exigence
// ici (génération d'identifiant serveur CHIF-5) — sans prétendre
// à la robustesse cryptographique d'un DRBG complet.
// Voir docs/dat.md, annexe B pour la justification.
func nouveauPRNGDeterministe(graine []byte) *prngDeterministe {
	d := &prngDeterministe{accum: graine}
	// Première itération pour amorcer l'état
	d.reapprovisionner()
	return d
}

// DANGER : ne pas utiliser pour de la dérivation de clé.
// prngDeterministe est un générateur déterministe simple par HMAC-SHA256.
// Il implémente io.Reader. Chaque lecture produit un bloc de
// HMAC-SHA256, et l'état est mis à jour après chaque bloc.
type prngDeterministe struct {
	accum []byte
	buf   []byte
	idx   int
}

func (d *prngDeterministe) Read(p []byte) (int, error) {
	lu := 0
	for lu < len(p) {
		if d.idx >= len(d.buf) {
			d.reapprovisionner()
		}
		n := copy(p[lu:], d.buf[d.idx:])
		d.idx += n
		lu += n
	}
	return lu, nil
}

func (d *prngDeterministe) reapprovisionner() {
	// HMAC-SHA256 simple : H(accum ‖ counter)
	h := sha256.New()
	h.Write(d.accum)
	var compteur [8]byte
	binary.BigEndian.PutUint64(compteur[:], uint64(len(d.buf)/sha256.Size))
	h.Write(compteur[:])
	d.buf = h.Sum(nil)
	// Mettre à jour l'accumulateur pour la prochaine itération
	h.Reset()
	h.Write(d.accum)
	h.Write(d.buf)
	d.accum = h.Sum(nil)
	d.idx = 0
}

// ChiffrerMotsAvecCle est un wrapper sur sceller pour le schéma
// CHIF-5 : chiffre avec une clé fournie et un blobSalt.
func ChiffrerMotsAvecCle(blobSalt, cle, clair []byte) ([]byte, error) {
	return sceller(VersionMots, blobSalt, cle, clair)
}

// ChiffrerAvecCle chiffre avec une clé fournie, sous la version
// indiquée. Pour CHIF-5 (VersionMots), le blobSalt est inclus
// dans l'en-tête. Pour VersionServeur, le sel est nil.
func ChiffrerAvecCle(version byte, blobSalt, cle, clair []byte) ([]byte, error) {
	var sel []byte
	switch version {
	case VersionCle:
		// CHIF-2 : sel nil, identique à VersionServeur
	case VersionServeur:
		// sel reste nil
	case VersionMots:
		sel = blobSalt
	default:
		return nil, fmt.Errorf("version de chiffrement non supportée par ChiffrerAvecCle : 0x%02x", version)
	}
	return sceller(version, sel, cle, clair)
}
