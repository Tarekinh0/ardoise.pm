package cli

import "fmt"

const aidePurge = `usage : ardoise purge [OPTIONS]

Efface le cache local du poste. Sans argument, purge les entrées expirées ;
avec « --tout », purge l'intégralité du cache.

Options :
      --tout   purge l'intégralité du cache, expirées ou non
` + aideCommunes

// cmdPurge efface le cache local (ADR-013) : par défaut les seules entrées
// expirées — les entrées « libre » (CACHE-3), sans échéance propre, sont
// conservées et ne partent qu'avec « --tout ». Un cache absent n'est pas
// une erreur : il n'y a rien à purger. Les décomptes sont rendus sur la
// sortie d'erreur (ou en JSON structuré avec « --json »).
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

	cache, err := cacheDuPoste(ctx)
	if err != nil {
		return err
	}
	var supprimees, conservees int
	if tout {
		supprimees, err = cache.PurgerTout()
	} else {
		supprimees, conservees, err = cache.PurgerExpirees()
	}
	if err != nil {
		return Erreurf(CodeErreur, "purge du cache : %v", err)
	}

	if com.json {
		return ecrireJSONSortie(ctx.Stdout, struct {
			Supprimees int `json:"supprimees"`
			Conservees int `json:"conservees"`
		}{supprimees, conservees})
	}
	s := nouvelleSortie(ctx, &com)
	s.infof("%s", fmt.Sprintf("Cache local : %d entrée(s) supprimée(s), %d conservée(s).", supprimees, conservees))
	return nil
}
