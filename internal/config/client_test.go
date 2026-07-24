package config

import (
	"os"
	"path/filepath"
	"testing"
)

func ecrireFichier(t *testing.T, chemin, contenu string) {
	t.Helper()
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChargerClientPreseance(t *testing.T) {
	rep := t.TempDir()
	poste := filepath.Join(rep, "poste.json")
	utilisateur := filepath.Join(rep, "utilisateur.json")
	ecrireFichier(t, poste, `{"endpoint":"https://poste.interne:8443","ac":"/etc/pki/ac.pem","cache":"/var/cache/ardoise"}`)
	ecrireFichier(t, utilisateur, `{"endpoint":"https://utilisateur.interne:8443"}`)

	env := map[string]string{"ARDOISE_AC": "/home/u/ac.pem"}
	c, err := ChargerClient([]string{poste, utilisateur}, func(nom string) string { return env[nom] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://utilisateur.interne:8443" {
		t.Errorf("le fichier utilisateur doit l'emporter, obtenu %q", c.Endpoint)
	}
	if c.AC != "/home/u/ac.pem" {
		t.Errorf("la variable d'environnement doit l'emporter, obtenu %q", c.AC)
	}
	if c.Cache != "/var/cache/ardoise" {
		t.Errorf("les champs non surchargés doivent rester, obtenu %q", c.Cache)
	}
}

func TestChargerClientEnvironnementComplet(t *testing.T) {
	env := map[string]string{
		"ARDOISE_ENDPOINT":   "https://env.interne:8443",
		"ARDOISE_AC":         "/e/ac.pem",
		"ARDOISE_CERTIFICAT": "/e/cert.pem",
		"ARDOISE_CLE":        "/e/cle.pem",
		"ARDOISE_PKCS11":     "pkcs11:token=adm",
		"ARDOISE_JETON":      "/e/jeton",
		"ARDOISE_CACHE":      "/e/cache",
	}
	c, err := ChargerClient(nil, func(nom string) string { return env[nom] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != env["ARDOISE_ENDPOINT"] || c.AC != env["ARDOISE_AC"] ||
		c.Certificat != env["ARDOISE_CERTIFICAT"] || c.Cle != env["ARDOISE_CLE"] ||
		c.PKCS11 != env["ARDOISE_PKCS11"] || c.Jeton != env["ARDOISE_JETON"] ||
		c.Cache != env["ARDOISE_CACHE"] {
		t.Errorf("surcharge d'environnement incomplète : %+v", c)
	}
}

func TestChargerClientFichierAbsentIgnore(t *testing.T) {
	c, err := ChargerClient([]string{filepath.Join(t.TempDir(), "absent.json")}, nil)
	if err != nil {
		t.Fatalf("un fichier absent doit être ignoré : %v", err)
	}
	if c.Endpoint != "" {
		t.Errorf("configuration vide attendue, obtenu %+v", c)
	}
}

func TestChargerClientChampInconnuRefuse(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "client.json")
	ecrireFichier(t, chemin, `{"endpoint":"https://x:1","proxy":"https://y:2"}`)
	if _, err := ChargerClient([]string{chemin}, nil); err == nil {
		t.Fatal("un champ inconnu doit être une erreur (décodage strict)")
	}
}

func TestChargerClientJSONInvalide(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "client.json")
	ecrireFichier(t, chemin, `{"endpoint":`)
	if _, err := ChargerClient([]string{chemin}, nil); err == nil {
		t.Fatal("un JSON illisible doit être une erreur")
	}
}
