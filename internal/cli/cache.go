package cli

import (
	"os"
	"path/filepath"
	"strings"

	"ardoise.pm/internal/client"
	"ardoise.pm/internal/config"
)

// cacheDuPoste résout l'emplacement du cache local — clé « cache » de la
// configuration client, variable ARDOISE_CACHE, défaut ~/.cache/ardoise
// (docs/man.md, FICHIERS) — et prépare le cache correspondant. Le
// répertoire n'est créé qu'à la première écriture, en 0700.
func cacheDuPoste(ctx *Contexte) (*client.Cache, error) {
	configClient, err := config.ChargerClient(ctx.CheminsConfigClient, ctx.Getenv)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	repertoire := configClient.Cache
	switch {
	case repertoire == "":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, Erreurf(CodeErreur, "emplacement du cache indéterminable : %v (renseignez la clé « cache » ou ARDOISE_CACHE)", err)
		}
		repertoire = filepath.Join(home, ".cache", "ardoise")
	case strings.HasPrefix(repertoire, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, Erreurf(CodeErreur, "emplacement du cache indéterminable : %v", err)
		}
		repertoire = filepath.Join(home, repertoire[2:])
	}
	return client.NouveauCache(repertoire), nil
}
