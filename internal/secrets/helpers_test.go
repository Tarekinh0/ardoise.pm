// Adapté de Qindu, paquet internal/pii — auxiliaire de tests repris de
// email_test.go, dont les tests eux-mêmes sont écartés avec les détecteurs
// de données personnelles (voir le commentaire du paquet, secrets.go).

package secrets

import "strings"

// stringsRepeat repeats s count times (test helper from the source repo).
func stringsRepeat(s string, count int) string {
	return strings.Repeat(s, count)
}
