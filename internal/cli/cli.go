// Package cli porte l'interface en ligne de commande d'ardoise : répartition
// des sous-commandes, options en français (docs/man.md), codes de retour
// (table 0..9) et sorties (--json, --silencieux, couleur).
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Contexte rassemble tout ce qu'une commande touche du monde extérieur, afin
// que les tests puissent tout substituer.
type Contexte struct {
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string

	// StdinTTY vaut faux lorsque l'entrée standard est redirigée : sans
	// sous-commande, « push » est alors implicite (docs/man.md).
	StdinTTY  bool
	StdoutTTY bool

	// CheminsConfigClient : fichiers client.json, ordre croissant de préséance.
	CheminsConfigClient []string

	// LireMotDePasse demande un mot de passe au terminal, écho coupé — le
	// manuel interdit tout passage en argument. Substituable par les tests ;
	// le mot de passe reste en []byte et l'appelant l'efface après usage.
	LireMotDePasse func(invite string) ([]byte, error)

	// Confirmer pose une question fermée sur le terminal de contrôle
	// (/dev/tty), la réponse par défaut étant NON : elle porte la
	// confirmation interactive de la détection de secrets (« --secrets
	// demander »). Nil lorsqu'aucun terminal n'existe : l'appelant refuse
	// alors l'opération plutôt que de la poursuivre sans confirmation.
	Confirmer func(question string) (bool, error)

	// LireMots saisit interactivement n mots mnémoniques sur /dev/tty.
	// Substituable par les tests ; le matériel saisi reste en []string et
	// l'appelant efface les dérivés après usage.
	LireMots func(n int) ([]string, error)
}

// ContexteSysteme construit le contexte réel du processus.
func ContexteSysteme(args []string) *Contexte {
	chemins := []string{"/etc/ardoise/client.json"}
	if home, err := os.UserHomeDir(); err == nil {
		chemins = append(chemins, filepath.Join(home, ".config", "ardoise", "client.json"))
	}
	return &Contexte{
		Args:                args,
		Stdin:               os.Stdin,
		Stdout:              os.Stdout,
		Stderr:              os.Stderr,
		Getenv:              os.Getenv,
		StdinTTY:            estTTY(os.Stdin),
		StdoutTTY:           estTTY(os.Stdout),
		CheminsConfigClient: chemins,
		LireMotDePasse:      lireMotDePasseTerminal,
		Confirmer:           confirmerTerminal,
		LireMots:            saisirMots,
	}
}

func estTTY(f *os.File) bool {
	infos, err := f.Stat()
	return err == nil && infos.Mode()&os.ModeCharDevice != 0
}

type commande func(*Contexte, []string) error

var commandes = map[string]commande{
	"push":    cmdPush,
	"get":     cmdGet,
	"info":    cmdInfo,
	"purge":   cmdPurge,
	"cle":     cmdCle,
	"serve":   cmdServe,
	"version": cmdVersion,
	"man":     cmdMan,
}

const usageGenerale = `usage :
  ardoise [push] [OPTIONS] [FICHIER]
  ardoise get [OPTIONS] IDENTIFIANT
  ardoise get [OPTIONS] -
  ardoise info [OPTIONS]
  ardoise purge [OPTIONS]
  ardoise cle --generer [OPTIONS]
  ardoise serve --config FICHIER [OPTIONS]
  ardoise version
  ardoise man

Sous-commandes :
  push     dépose un contenu et affiche son identifiant (implicite quand
           l'entrée standard est redirigée)
  get      récupère un contenu sur la sortie standard
  info     affiche la politique effective d'une instance
  purge    efface le cache local du poste
  cle      génère le matériel de destinataire du chiffrement
           multi-destinataires (--pour avec annuaire)
  serve    démarre une instance
  version  affiche la version, l'empreinte du binaire et l'identifiant
           de compilation
  man      affiche le manuel complet au format Markdown

« ardoise <commande> --aide » détaille chaque commande.`

// Executer répartit les arguments vers la commande visée et retourne le code
// de sortie du processus. C'est l'unique point de traduction erreur → code.
func Executer(ctx *Contexte) int {
	nom, reste, aide, err := resoudreCommande(ctx)
	if err != nil {
		fmt.Fprintf(ctx.Stderr, "ardoise : %v\n%s\n", err, usageGenerale)
		return CodeUsage
	}
	if aide {
		fmt.Fprintln(ctx.Stdout, usageGenerale)
		return CodeOK
	}
	if err := commandes[nom](ctx, reste); err != nil {
		var e *Erreur
		if errors.As(err, &e) {
			if e.Message != "" {
				fmt.Fprintf(ctx.Stderr, "ardoise : %s\n", e.Message)
			}
			return e.Code
		}
		fmt.Fprintf(ctx.Stderr, "ardoise : %v\n", err)
		return CodeErreur
	}
	return CodeOK
}

// resoudreCommande applique la règle du manuel : sans sous-commande, avec
// une entrée standard redirigée, « push » est implicite ; tout premier
// argument inconnu est traité comme un argument de push (commande par
// défaut : « ardoise [push] [OPTIONS] [FICHIER] »).
func resoudreCommande(ctx *Contexte) (nom string, reste []string, aide bool, err error) {
	args := ctx.Args
	if len(args) == 0 {
		if ctx.StdinTTY {
			return "", nil, false, errors.New("aucune commande et aucune entrée redirigée")
		}
		return "push", nil, false, nil
	}
	if _, connue := commandes[args[0]]; connue {
		return args[0], args[1:], false, nil
	}
	switch args[0] {
	case "aide", "--aide", "-h", "help":
		return "", nil, true, nil
	}
	return "push", args, false, nil
}
