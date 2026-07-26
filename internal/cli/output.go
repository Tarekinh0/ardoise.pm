package cli

import (
	"fmt"
	"io"
)

// sortie centralise l'écriture vers l'utilisateur : messages informatifs sur
// la sortie d'erreur (supprimables par --silencieux), colorisation soumise à
// --sans-couleur, à ARDOISE_NO_COLOR et à la détection de terminal.
type sortie struct {
	stdout     io.Writer
	stderr     io.Writer
	json       bool
	silencieux bool
	couleur    bool
}

func nouvelleSortie(ctx *Contexte, com *optionsCommunes) *sortie {
	return &sortie{
		stdout:     ctx.Stdout,
		stderr:     ctx.Stderr,
		json:       com.json,
		silencieux: com.silencieux,
		couleur:    !com.sansCouleur && ctx.StdoutTTY && ctx.Getenv("ARDOISE_NO_COLOR") == "",
	}
}

// infof écrit un message informatif sur la sortie d'erreur, sauf en mode
// silencieux. Les refus et erreurs ne passent jamais par ici : ils sont
// portés par Erreur et toujours affichés.
func (s *sortie) infof(format string, args ...any) {
	if s.silencieux {
		return
	}
	fmt.Fprintf(s.stderr, format+"\n", args...)
}

// gras met un texte en gras lorsque la colorisation est active.
func (s *sortie) gras(texte string) string {
	if !s.couleur {
		return texte
	}
	return "\x1b[1m" + texte + "\x1b[0m"
}
