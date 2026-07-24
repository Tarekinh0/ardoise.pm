package cli

import (
	"flag"
	"fmt"
	"io"
)

// nouveauFS crée un jeu d'options silencieux : les erreurs d'analyse sont
// reformulées par analyserFlags et l'aide est portée par -h/--aide.
func nouveauFS(nom string) *flag.FlagSet {
	fs := flag.NewFlagSet(nom, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// analyserFlags analyse les arguments et traduit toute erreur du paquet flag
// en erreur d'usage (code 2).
func analyserFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return erreurUsage("options invalides : %v", err)
	}
	return nil
}

// optionsCommunes porte les options communes du manuel (« OPTIONS
// COMMUNES ») ; les formes longues et courtes visent la même variable.
type optionsCommunes struct {
	endpoint    string
	silencieux  bool
	json        bool
	sansCouleur bool
	aide        bool
}

func (o *optionsCommunes) enregistrer(fs *flag.FlagSet) {
	fs.StringVar(&o.endpoint, "endpoint", "", "instance à contacter")
	fs.StringVar(&o.endpoint, "e", "", "")
	fs.BoolVar(&o.silencieux, "silencieux", false, "supprime les messages informatifs")
	fs.BoolVar(&o.silencieux, "q", false, "")
	fs.BoolVar(&o.json, "json", false, "sortie structurée")
	fs.BoolVar(&o.sansCouleur, "sans-couleur", false, "désactive la colorisation")
	fs.BoolVar(&o.aide, "aide", false, "affiche l'aide")
	fs.BoolVar(&o.aide, "h", false, "")
}

// optionsAuthClient porte le matériel d'authentification côté client
// (docs/man.md, « AUTHENTIFICATION CLIENT »). En phase A, seul le couple
// certificat/clé et l'AC sont exploités (par « info ») ; --pkcs11 et --jeton
// sont acceptés et validés, leur emploi arrive en phase authentification.
type optionsAuthClient struct {
	certificat string
	cle        string
	pkcs11     string
	jeton      string
	ac         string
}

func (o *optionsAuthClient) enregistrer(fs *flag.FlagSet) {
	fs.StringVar(&o.certificat, "certificat", "", "certificat client")
	fs.StringVar(&o.cle, "cle", "", "clé privée du certificat client")
	fs.StringVar(&o.pkcs11, "pkcs11", "", "URI du support matériel")
	fs.StringVar(&o.jeton, "jeton", "", "fichier contenant le jeton")
	fs.StringVar(&o.ac, "ac", "", "autorité de certification de l'instance")
}

// verifierPositionnels refuse tout argument positionnel excédentaire.
func verifierPositionnels(fs *flag.FlagSet, maximum int, usage string) error {
	if fs.NArg() > maximum {
		return erreurUsage("argument inattendu « %s » (usage : %s)", fs.Arg(maximum), usage)
	}
	return nil
}

const aideCommunes = `
Options communes :
  -e, --endpoint URL   instance à contacter (défaut : ARDOISE_ENDPOINT,
                       puis configuration client)
  -q, --silencieux     supprime les messages informatifs (les refus restent)
      --json           sortie structurée pour usage en script
      --sans-couleur   désactive la colorisation (aussi : ARDOISE_NO_COLOR)
  -h, --aide           affiche cette aide`

const aideAuthClient = `
Authentification client :
      --certificat CHEMIN  certificat client
      --cle CHEMIN         clé privée du certificat client
      --pkcs11 URI         clé portée par un support matériel
      --jeton CHEMIN       fichier contenant le jeton d'identité
      --ac CHEMIN          AC de confiance pour valider l'instance`

func afficherAide(w io.Writer, texte string) {
	fmt.Fprintln(w, texte)
}
