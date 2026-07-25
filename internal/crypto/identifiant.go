package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// TailleIDServeur est la longueur de l'identifiant serveur d'une ardoise.
const TailleIDServeur = 12

// alphabetID est l'alphabet des identifiants serveur : minuscules et
// chiffres 2 à 9 (docs/dat.md §4.3), soit 34 symboles — les chiffres 0 et 1
// sont exclus pour éviter toute confusion visuelle avec o et l.
const alphabetID = "abcdefghijklmnopqrstuvwxyz23456789"

// NouvelIDServeur produit un identifiant serveur de 12 caractères tirés de
// crypto/rand. L'alphabet comptant 34 symboles, la réduction d'un octet
// aléatoire se fait par échantillonnage avec rejet : seuls les octets
// inférieurs à 238 (= 7 × 34) sont acceptés, ce qui rend chaque symbole
// exactement équiprobable.
func NouvelIDServeur() (string, error) {
	const borne = byte(238) // plus grand multiple de 34 inférieur à 256
	id := make([]byte, 0, TailleIDServeur)
	tampon := make([]byte, 32)
	for len(id) < TailleIDServeur {
		if _, err := rand.Read(tampon); err != nil {
			return "", fmt.Errorf("génération de l'identifiant : %w", err)
		}
		for _, b := range tampon {
			if b >= borne {
				continue // rejet : éviterait un biais vers le début de l'alphabet
			}
			id = append(id, alphabetID[b%byte(len(alphabetID))])
			if len(id) == TailleIDServeur {
				break
			}
		}
	}
	return string(id), nil
}

// IDServeurValide indique si id a la forme exacte d'un identifiant serveur :
// 12 caractères de l'alphabet [a-z2-9].
func IDServeurValide(id string) bool {
	if len(id) != TailleIDServeur {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !strings.ContainsRune(alphabetID, rune(id[i])) {
			return false
		}
	}
	return true
}

// FormatIdentifiant assemble l'identifiant remis à l'émetteur :
// « <id-serveur>#<clé en base64url brut> ». Le séparateur « # » garantit
// qu'en contexte d'URL le matériel de clé reste dans le fragment, jamais
// transmis au serveur (docs/dat.md §4.3). Sans matériel de clé (CHIF-3),
// l'identifiant se réduit à l'identifiant serveur.
func FormatIdentifiant(id string, cle []byte) string {
	if len(cle) == 0 {
		return id
	}
	return id + "#" + base64.RawURLEncoding.EncodeToString(cle)
}

// FormatIdentifiantMultiDest assemble l'identifiant d'une ardoise chiffrée
// pour plusieurs destinataires (CHIF-MD) : « <id-serveur>#md ». Le fragment
// est une SENTINELLE, jamais une clé — il signale au client de récupération
// qu'aucune clé symétrique n'est attendue, l'ouverture exigeant la clé
// privée du destinataire ; l'octet de version du chiffré reste seul
// autoritaire sur le schéma (multidest.go).
func FormatIdentifiantMultiDest(id string) string {
	return id + "#" + SentinelleMultiDest
}

// ParseIdentifiant décompose un identifiant saisi par l'utilisateur en
// identifiant serveur et matériel de clé (nil en l'absence de fragment).
// Seul l'identifiant serveur est destiné à être transmis à l'instance.
func ParseIdentifiant(s string) (id string, cle []byte, err error) {
	s = strings.TrimSpace(s)
	id, fragment, avecFragment := strings.Cut(s, "#")
	if !IDServeurValide(id) {
		return "", nil, errors.New("identifiant invalide : la partie serveur doit compter 12 caractères parmi a-z et 2-9")
	}
	if !avecFragment {
		return id, nil, nil
	}
	if fragment == SentinelleMultiDest {
		// Sentinelle CHIF-MD : aucune clé dans l'identifiant, l'ouverture
		// passera par la clé privée du destinataire (multidest.go).
		return id, nil, nil
	}
	cle, errDecodage := base64.RawURLEncoding.DecodeString(fragment)
	if errDecodage != nil || len(cle) != TailleCle {
		// Le fragment fautif n'est jamais répété dans le message : il
		// pourrait être un matériel de clé presque valide.
		return "", nil, errors.New("identifiant invalide : le matériel de clé après « # » est illisible")
	}
	return id, cle, nil
}
