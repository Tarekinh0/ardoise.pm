package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Empreinte calcule l'empreinte SHA-256 du chiffré, en hexadécimal
// minuscule. C'est la valeur retournée au dépôt, vérifiée à la
// récupération, et versée aux métadonnées d'imputabilité (ADR-005).
func Empreinte(chiffre []byte) string {
	somme := sha256.Sum256(chiffre)
	return hex.EncodeToString(somme[:])
}

// EmpreintesEgales compare deux empreintes hexadécimales en temps constant
// (annexe B : comparaisons en temps constant pour tout secret ou jeton).
// Le préfixe « sha256: » et la casse sont normalisés avant comparaison ;
// toute valeur qui n'est pas une empreinte SHA-256 valide est inégale.
func EmpreintesEgales(a, b string) bool {
	octetsA, okA := decoderEmpreinte(a)
	octetsB, okB := decoderEmpreinte(b)
	if !okA || !okB {
		return false
	}
	return subtle.ConstantTimeCompare(octetsA, octetsB) == 1
}

func decoderEmpreinte(s string) ([]byte, bool) {
	s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
	octets, err := hex.DecodeString(s)
	if err != nil || len(octets) != sha256.Size {
		return nil, false
	}
	return octets, true
}
