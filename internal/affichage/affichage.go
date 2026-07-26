// Package affichage fournit des fonctions utilitaires de mise en forme
// partagées entre plusieurs paquets (config, cli) sans créer de dépendance
// architecturale entre eux.
package affichage

import (
	"strings"
	"unicode/utf8"
)

// PadDroite complète une chaîne à droite jusqu'à n caractères, comptés en
// runes pour que les accents ne cassent pas l'alignement des tableaux.
func PadDroite(s string, n int) string {
	manque := n - utf8.RuneCountInString(s)
	if manque <= 0 {
		return s
	}
	return s + strings.Repeat(" ", manque)
}
