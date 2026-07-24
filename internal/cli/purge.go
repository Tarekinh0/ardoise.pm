package cli

const aidePurge = `usage : ardoise purge [OPTIONS]

Efface le cache local du poste. Sans argument, purge les entrées expirées ;
avec « --tout », purge l'intégralité du cache.

Options :
      --tout   purge l'intégralité du cache, expirées ou non
` + aideCommunes

// cmdPurge analyse et valide les options ; la gestion du cache local arrive
// dans une phase ultérieure (ARDOISE-0007).
func cmdPurge(ctx *Contexte, args []string) error {
	fs := nouveauFS("purge")
	var com optionsCommunes
	com.enregistrer(fs)
	var tout bool
	fs.BoolVar(&tout, "tout", false, "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aidePurge)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise purge [OPTIONS]"); err != nil {
		return err
	}

	return Erreurf(CodeErreur, "la commande « purge » n'est pas disponible dans cette version : le cache local arrive dans une phase ultérieure")
}
