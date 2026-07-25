package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// instanceMinimale construit une instance valide dont muter ajuste le JSON.
func instanceMinimale(t *testing.T, muter func(map[string]map[string]any)) (*Instance, []Probleme) {
	t.Helper()
	m := map[string]map[string]any{
		"instance":  {"nom": "test", "mode": "aveugle"},
		"auth":      {"mecanisme": "jeton", "jetons": "/etc/ardoise/jetons.json"},
		"transport": {"certificat": "/tmp/c.pem", "cle": "/tmp/c.key"},
		"marquage":  {"actif": true, "libelle": "DR"},
	}
	if muter != nil {
		muter(m)
	}
	donnees, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	inst, problemes, err := Analyser(donnees)
	if err != nil {
		t.Fatal(err)
	}
	return inst, problemes
}

func TestPolitiqueExposeCacheEtDestinataires(t *testing.T) {
	inst, problemes := instanceMinimale(t, func(m map[string]map[string]any) {
		m["cache"] = map[string]any{"politique": "borne"}
	})
	if len(problemes) != 0 {
		t.Fatalf("problèmes : %v", problemes)
	}
	p := inst.Politique()
	if p.CachePolitique != "borne" {
		t.Errorf("cache_politique = %q", p.CachePolitique)
	}
	if !p.DestinatairesAdmis {
		t.Error("destinataires_admis doit être vrai hors identification déclarative")
	}
	// La forme JSON — celle de GET /v1/politique — porte bien les champs.
	donnees, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, champ := range []string{`"cache_politique":"borne"`, `"destinataires_admis":true`} {
		if !strings.Contains(string(donnees), champ) {
			t.Errorf("champ %s absent de la politique JSON", champ)
		}
	}
}

func TestPolitiqueDestinatairesRefusesSousDeclaratif(t *testing.T) {
	inst, problemes := instanceMinimale(t, func(m map[string]map[string]any) {
		m["auth"] = map[string]any{"mecanisme": "declaratif"}
	})
	if len(problemes) != 0 {
		t.Fatalf("problèmes : %v", problemes)
	}
	if inst.Politique().DestinatairesAdmis {
		t.Error("destinataires_admis doit être faux sous identification déclarative")
	}
}

func TestAuthGroupesValidation(t *testing.T) {
	// Acceptée avec un mécanisme authentifié.
	_, problemes := instanceMinimale(t, func(m map[string]map[string]any) {
		m["auth"] = map[string]any{"mecanisme": "jeton", "jetons": "/etc/ardoise/jetons.json", "groupes": "/etc/ardoise/groupes.json"}
	})
	if len(problemes) != 0 {
		t.Fatalf("auth.groupes avec « jeton » : problèmes inattendus : %v", problemes)
	}
	// Refusée sous identification déclarative, où « --pour » l'est aussi.
	_, problemes = instanceMinimale(t, func(m map[string]map[string]any) {
		m["auth"] = map[string]any{"mecanisme": "declaratif", "groupes": "/etc/ardoise/groupes.json"}
	})
	trouve := false
	for _, p := range problemes {
		if p.Champ == "auth.groupes" {
			trouve = true
		}
	}
	if !trouve {
		t.Errorf("auth.groupes sous « declaratif » doit être signalé : %v", problemes)
	}
}

func TestClientAnnuaireEtClePrivee(t *testing.T) {
	repertoire := t.TempDir()
	chemin := filepath.Join(repertoire, "client.json")
	contenu := `{"endpoint": "https://ardoise.interne:8443", "annuaire": "/etc/ardoise/annuaire.json", "cle_privee_ardoise": "/home/u/.config/ardoise/cle"}`
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := ChargerClient([]string{chemin}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Annuaire != "/etc/ardoise/annuaire.json" || c.ClePriveeArdoise != "/home/u/.config/ardoise/cle" {
		t.Errorf("clés multi-destinataires : %+v", c)
	}
	// Les variables d'environnement l'emportent sur le fichier.
	env := map[string]string{
		"ARDOISE_ANNUAIRE":   "/autre/annuaire.json",
		"ARDOISE_CLE_PRIVEE": "/autre/cle",
	}
	c, err = ChargerClient([]string{chemin}, func(nom string) string { return env[nom] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Annuaire != "/autre/annuaire.json" || c.ClePriveeArdoise != "/autre/cle" {
		t.Errorf("surcharge d'environnement : %+v", c)
	}
}
