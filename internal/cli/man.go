package cli

import (
	_ "embed"
	"fmt"
)

//go:generate cp ../../docs/man.md manpage.md

//go:embed manpage.md
var pageManuel string

const aideMan = `usage : ardoise man [OPTIONS]

Affiche le manuel complet (ARDOISE(1)) sur la sortie standard, au format
Markdown. Cette commande ne contacte aucune instance.
`

func cmdMan(ctx *Contexte, args []string) error {
	fs := nouveauFS("man")
	var com optionsCommunes
	com.enregistrer(fs)
	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideMan)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise man"); err != nil {
		return err
	}
	fmt.Fprint(ctx.Stdout, pageManuel)
	return nil
}
