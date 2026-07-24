package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Version et IDCompilation sont fixés à la construction via -ldflags
// (voir build.sh) : la version publiée et l'identifiant de compilation
// reproductible (ES-9, builds reproductibles).
var (
	Version       = "0.1.0-dev"
	IDCompilation = "inconnu"
)

const aideVersion = `usage : ardoise version

Affiche la version, l'empreinte SHA-256 du binaire en cours d'exécution et
l'identifiant de compilation reproductible.
` + aideCommunes

func cmdVersion(ctx *Contexte, args []string) error {
	fs := nouveauFS("version")
	var com optionsCommunes
	com.enregistrer(fs)
	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideVersion)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise version"); err != nil {
		return err
	}

	empreinte := empreinteBinaire()
	if com.json {
		return ecrireJSONSortie(ctx.Stdout, struct {
			Version     string `json:"version"`
			Empreinte   string `json:"empreinte"`
			Compilation string `json:"compilation"`
		}{Version, empreinte, IDCompilation})
	}
	fmt.Fprintf(ctx.Stdout, "ardoise %s\nEmpreinte du binaire       : %s\nIdentifiant de compilation : %s\n",
		Version, empreinte, IDCompilation)
	return nil
}

// empreinteBinaire calcule l'empreinte SHA-256 de l'exécutable courant, à
// rapprocher des empreintes publiées avec les paquets signés (DIST-1).
func empreinteBinaire() string {
	executable, err := os.Executable()
	if err != nil {
		return "indisponible"
	}
	f, err := os.Open(executable)
	if err != nil {
		return "indisponible"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "indisponible"
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func ecrireJSONSortie(w io.Writer, corps any) error {
	donnees, err := json.MarshalIndent(corps, "", "  ")
	if err != nil {
		return Erreurf(CodeErreur, "sérialisation JSON : %v", err)
	}
	_, err = fmt.Fprintln(w, string(donnees))
	if err != nil {
		return Erreurf(CodeErreur, "écriture de la sortie : %v", err)
	}
	return nil
}
