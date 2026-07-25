// Adapté de Qindu, paquet internal/pii — fichier entity_test.go (origine
// AGPL-3.0 ; reprise approuvée par le titulaire des droits, pont de
// licence suivi au registre des risques R-006). Cas transposés vers les
// seuls types d'authentifiants conservés.

package secrets

import (
	"fmt"
	"strings"
	"testing"
)

func TestSafeStringNeverContainsValue(t *testing.T) {
	e := Entity{
		Value:      "ghp_SuperSecretValue1234567890abcdef",
		Type:       Secret,
		Source:     SourcePrefix,
		Confidence: 0.85,
		Start:      10,
		End:        46,
	}
	for nom, rendu := range map[string]string{
		"SafeString": e.SafeString(),
		"String":     e.String(),
		"Sprintf %s": fmt.Sprintf("%s", e),
		"Sprintf %v": fmt.Sprintf("%v", e),
	} {
		if strings.Contains(rendu, e.Value) {
			t.Errorf("%s reproduit la valeur détectée : %q", nom, rendu)
		}
	}
}

func TestSafeStringFormat(t *testing.T) {
	e := Entity{
		Value:      "a.b.c",
		Type:       JWT,
		Source:     SourceStructural,
		Confidence: 0.9,
		Start:      0,
		End:        5,
	}
	attendu := "JWT(src=structural, conf=0.90, pos=0-5)"
	if e.SafeString() != attendu {
		t.Errorf("SafeString = %q, attendu %q", e.SafeString(), attendu)
	}
}
