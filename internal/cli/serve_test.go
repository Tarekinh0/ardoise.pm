package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ardoise.pm/internal/config"
)

// configurationValide reproduit l'exemple du manuel ; les chemins TLS ne
// sont pas résolus par --verifier ni --politique (seul le démarrage les lit).
const configurationValide = `{
	"instance":  {"nom": "ardoise-adm-zone-reseau", "mode": "aveugle", "ecoute": "127.0.0.1:8443"},
	"auth":      {"mecanisme": "mtls", "ac_clients": "/etc/ardoise/ac-clients.pem"},
	"contenu":   {"chiffrement": "cle", "taille_max": "256Kio"},
	"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
	"cache":     {"politique": "interdit"},
	"journal":   {"destination": "syslog+tls://journal.adm.interne:6514", "chainage": true},
	"transport": {"certificat": "/etc/ardoise/instance.pem", "cle": "/etc/ardoise/instance.key", "version_min": "1.3"},
	"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"}
}`

func ecrireConfiguration(t *testing.T, contenu string) string {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "ardoise.json")
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	return chemin
}

func TestServeSansConfig(t *testing.T) {
	r := executer(t, []string{"serve"})
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d", r.code, CodeUsage)
	}
	if !strings.Contains(r.stderr, "--config") {
		t.Errorf("l'option manquante doit être citée :\n%s", r.stderr)
	}
}

func TestServeConfigIllisible(t *testing.T) {
	r := executer(t, []string{"serve", "--config", filepath.Join(t.TempDir(), "absent.json")})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
}

func TestServeVerifierConforme(t *testing.T) {
	chemin := ecrireConfiguration(t, configurationValide)
	r := executer(t, []string{"serve", "--config", chemin, "--verifier"})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
	for _, motif := range []string{
		"Politique effective :",
		"Identification",
		"AUTH-2",
		"CHIF-2",
		"RET-2",
		"TTL-2",
		"CACHE-1",
		"ANA-3",
		"JOURN-1",
		"TLS-2",
		"MARQ-1",
		"Configuration conforme aux minima II 901. Aucune incohérence détectée.",
	} {
		if !strings.Contains(r.stdout, motif) {
			t.Errorf("motif %q absent :\n%s", motif, r.stdout)
		}
	}
}

func TestServeVerifierIncoherente(t *testing.T) {
	incoherente := strings.Replace(configurationValide, `"mode": "aveugle"`, `"mode": "analyse"`, 1)
	chemin := ecrireConfiguration(t, incoherente)
	r := executer(t, []string{"serve", "-c", chemin, "--verifier"})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
	if !strings.Contains(r.stdout, "Incohérences détectées :") || !strings.Contains(r.stdout, "analyse.icap_url") {
		t.Errorf("les incohérences doivent être détaillées :\n%s", r.stdout)
	}
}

func TestServePolitique(t *testing.T) {
	chemin := ecrireConfiguration(t, configurationValide)
	r := executer(t, []string{"serve", "--config", chemin, "--politique"})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
	var politique config.Politique
	if err := json.Unmarshal([]byte(r.stdout), &politique); err != nil {
		t.Fatalf("JSON illisible : %v\n%s", err, r.stdout)
	}
	if politique.Instance != "ardoise-adm-zone-reseau" || len(politique.Options) != 9 || !politique.ConformeII901 {
		t.Errorf("politique inattendue : %+v", politique)
	}
}

func TestServePolitiqueConfigInvalide(t *testing.T) {
	invalide := strings.Replace(configurationValide, `"taille_max": "256Kio"`, `"taille_max": "beaucoup"`, 1)
	chemin := ecrireConfiguration(t, invalide)
	r := executer(t, []string{"serve", "--config", chemin, "--politique"})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
	if !strings.Contains(r.stderr, "contenu.taille_max") {
		t.Errorf("le champ fautif doit être cité :\n%s", r.stderr)
	}
}

func TestServeDemarrageRefuseSansMaterielTLS(t *testing.T) {
	// Chemins TLS inexistants : la configuration est cohérente mais le
	// démarrage doit être refusé au chargement du matériel.
	chemin := ecrireConfiguration(t, configurationValide)
	r := executer(t, []string{"serve", "--config", chemin})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
	if !strings.Contains(r.stderr, "TLS") {
		t.Errorf("le refus doit mentionner le matériel TLS :\n%s", r.stderr)
	}
}
