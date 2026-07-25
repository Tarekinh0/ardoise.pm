package cli

import (
	"fmt"
	"strings"

	"ardoise.pm/internal/config"
)

const aideInfo = `usage : ardoise info [OPTIONS]

Affiche la configuration effective de l'instance : mode, mécanisme
d'identification exigé, bornes de durée de vie et de taille, régime
d'analyse, politique de rémanence, niveau de marquage. Ne dépose rien et ne
consomme aucune ardoise.
` + aideCommunes + aideAuthClient

// cmdInfo interroge GET /v1/politique sur l'instance et restitue la
// politique effective (affichage humain, ou JSON brut avec --json).
// PR-101 : le client HTTP est celui de preparerClient (via le package
// client), garantissant un timeout cohérent avec les autres commandes
// (push, get) — plus de client HTTP ad hoc avec timeout divergent.
func cmdInfo(ctx *Contexte, args []string) error {
	fs := nouveauFS("info")
	var com optionsCommunes
	com.enregistrer(fs)
	var auth optionsAuthClient
	auth.enregistrer(fs)
	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideInfo)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise info [OPTIONS]"); err != nil {
		return err
	}
	s := nouvelleSortie(ctx, &com)

	cl, _, err := preparerClient(ctx, &com, &auth)
	if err != nil {
		return err
	}

	politique, err := cl.Politique()
	if err != nil {
		return traduireErreurClient(err)
	}

	if com.json {
		return ecrireJSONSortie(ctx.Stdout, politique)
	}
	fmt.Fprint(ctx.Stdout, rendreInfo(politique, s))
	return nil
}

// rendreInfo restitue la politique à la manière de l'exemple du manuel.
func rendreInfo(p *config.Politique, s *sortie) string {
	var b strings.Builder
	ligne := func(titre, valeur string) {
		fmt.Fprintf(&b, "%s: %s\n", s.gras(padDroite(titre, 21)), valeur)
	}
	ligne("Instance", p.Instance)
	ligne("Mode", texteMode(p.Mode))
	if o, ok := p.Option(config.DimIdentification); ok {
		ligne("Identification", fmt.Sprintf("%s (%s)", o.Libelle, o.ID))
	}
	ligne("Durée de vie", fmt.Sprintf("%s maximum, %s par défaut", p.DureeMax, p.DureeDefaut))
	ligne("Taille maximale", p.TailleMax)
	ligne("Lecture unique", texteLectureUnique(p.LectureUnique))
	if o, ok := p.Option(config.DimAnalyse); ok {
		ligne("Analyse de contenu", texteAnalyse(o))
	}
	if o, ok := p.Option(config.DimRemanence); ok {
		ligne("Rémanence locale", texteCache(o))
	}
	if o, ok := p.Option(config.DimJournalisation); ok {
		ligne("Journalisation", o.Libelle)
	}
	if p.MarquageActif {
		ligne("Marquage", p.MarquageLibelle)
	} else {
		ligne("Marquage", "aucun")
	}
	return b.String()
}

func texteMode(mode string) string {
	switch mode {
	case config.ModeAveugle:
		return "aveugle (le serveur ne peut à aucun moment lire les contenus)"
	case config.ModeAnalyse:
		return "analysé (le serveur analyse les contenus déposés)"
	}
	return mode
}

func texteLectureUnique(valeur string) string {
	switch valeur {
	case config.LectureUniqueImposee:
		return "imposée à chaque dépôt"
	case config.LectureUniqueAuChoix:
		return "au choix de l'émetteur"
	case config.LectureUniqueInterdit:
		return "interdite"
	}
	return valeur
}

func texteAnalyse(o config.OptionEffective) string {
	switch o.ID {
	case "ANA-1", "ANA-2":
		return "ICAP, bloquante"
	case "ANA-3":
		return "détection de secrets côté client"
	case "ANA-4":
		return "aucune"
	}
	return o.Libelle
}

func texteCache(o config.OptionEffective) string {
	switch o.ID {
	case "CACHE-1":
		return "interdite"
	case "CACHE-2":
		return "autorisée, bornée à l'échéance"
	case "CACHE-3":
		return "libre"
	}
	return o.Libelle
}
