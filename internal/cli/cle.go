package cli

import (
	"encoding/base64"
	"fmt"
	"os"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
)

const aideCle = `usage : ardoise cle --generer [--fichier CHEMIN]

Génère le matériel de destinataire du chiffrement multi-destinataires
(« --pour » avec annuaire) : une clé privée X25519, écrite dans un fichier
aux droits 0600, et la clé publique correspondante, affichée en base64 sur
la sortie standard — c'est elle qui rejoint l'annuaire de l'entité.

Options :
      --generer         génère une nouvelle paire (requis)
      --fichier CHEMIN  fichier de la clé privée (défaut : la clé
                        « cle_privee_ardoise » de la configuration client
                        ou ARDOISE_CLE_PRIVEE)
` + aideCommunes

// cmdCle porte la gestion du matériel de destinataire (CHIF-MD, ADR-014
// cas a). Cette version ne sait que générer : la distribution des clés
// publiques (annuaire) et le renouvellement relèvent de l'IGC de l'entité —
// cette commande n'est qu'un POINT D'ANCRAGE en attendant cette
// intégration, documentée comme telle (docs/dat.md, ADR-014 : « suppose un
// annuaire de clés publiques, donc une IGC opérationnelle »).
func cmdCle(ctx *Contexte, args []string) error {
	fs := nouveauFS("cle")
	var com optionsCommunes
	com.enregistrer(fs)
	var generer bool
	var fichier string
	fs.BoolVar(&generer, "generer", false, "")
	fs.StringVar(&fichier, "fichier", "", "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideCle)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise cle --generer [--fichier CHEMIN]"); err != nil {
		return err
	}
	if !generer {
		return erreurUsage("« ardoise cle » ne sait que générer : utilisez « --generer »")
	}

	if fichier == "" {
		configClient, err := config.ChargerClient(ctx.CheminsConfigClient, ctx.Getenv)
		if err != nil {
			return Erreurf(CodeErreur, "%v", err)
		}
		fichier = configClient.ClePriveeArdoise
	}
	if fichier == "" {
		return erreurUsage("aucun fichier de clé privée : utilisez « --fichier », la clé « cle_privee_ardoise » de la configuration client ou ARDOISE_CLE_PRIVEE")
	}

	privee, publique, err := crypto.GenererClePriveeMD()
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}
	defer crypto.Effacer(privee)

	// O_EXCL : une clé privée existante n'est JAMAIS écrasée — la perdre,
	// c'est perdre l'accès à tout contenu chiffré pour elle.
	f, err := os.OpenFile(fichier, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Erreurf(CodeErreur, "écriture de la clé privée : %v (une clé existante n'est jamais écrasée)", err)
	}
	// A.3-2 : La clé privée est écrite directement dans le fichier via
	// un encodeur base64 en continu, sans passer par une chaîne Go
	// intermédiaire. Les chaînes Go sont immuables : une conversion en
	// string par EncodeToString survivrait au ramasse-miettes, même après
	// l'appel à crypto.Effacer. L'écriture directe évite cette copie.
	encodeur := base64.NewEncoder(base64.StdEncoding, f)
	_, err = encodeur.Write(privee)
	if errFermetureE := encodeur.Close(); err == nil {
		err = errFermetureE
	}
	_, err = fmt.Fprintln(f)
	if errFermeture := f.Close(); err == nil {
		err = errFermeture
	}
	if err != nil {
		os.Remove(fichier)
		return Erreurf(CodeErreur, "écriture de la clé privée : %v", err)
	}

	clePublique := base64.StdEncoding.EncodeToString(publique)
	if com.json {
		return ecrireJSONSortie(ctx.Stdout, struct {
			ClePublique string `json:"cle_publique"`
			Fichier     string `json:"fichier"`
		}{clePublique, fichier})
	}
	s := nouvelleSortie(ctx, &com)
	s.infof("Clé privée écrite dans %s (0600). La clé publique ci-dessous rejoint l'annuaire de l'entité :", fichier)
	fmt.Fprintln(ctx.Stdout, clePublique)
	return nil
}
