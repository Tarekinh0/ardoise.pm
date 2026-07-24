package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenduVerificationConforme(t *testing.T) {
	inst := analyserSansProbleme(t, enJSON(t, configComplete()))
	rendu := inst.RenduVerification(nil)

	for _, motif := range []string{
		"Politique effective :",
		"Identification",
		"AUTH-2",
		"(R)",
		"certificat client, AC interne",
		"Durée de vie",
		"TTL-2",
		"24h maximum",
		"Rémanence client",
		"CACHE-1",
		"JOURN-1",
		"(R+)",
		"ANA-3",
		"(R-)",
		"TLS 1.3, épinglage actif",
		"« DIFFUSION RESTREINTE »",
		"Configuration conforme aux minima II 901. Aucune incohérence détectée.",
	} {
		if !strings.Contains(rendu, motif) {
			t.Errorf("motif %q absent du rendu :\n%s", motif, rendu)
		}
	}
}

func TestRenduVerificationNonConforme(t *testing.T) {
	m := configComplete()
	m["journal"]["destination"] = "aucun"
	m["journal"]["chainage"] = false
	inst := analyserSansProbleme(t, enJSON(t, m))
	rendu := inst.RenduVerification(nil)
	if !strings.Contains(rendu, "NON conforme aux minima II 901") {
		t.Errorf("verdict de non-conformité attendu :\n%s", rendu)
	}
	if !strings.Contains(rendu, "JOURN-4") {
		t.Errorf("l'écart JOURN-4 doit être cité :\n%s", rendu)
	}
	if !strings.Contains(rendu, "Aucune incohérence détectée.") {
		t.Errorf("configuration cohérente : la mention doit rester :\n%s", rendu)
	}
}

func TestRenduVerificationIncoherences(t *testing.T) {
	m := configComplete()
	m["instance"]["mode"] = "analyse" // sans icap_url ni chiffrement serveur
	inst, problemes, err := Analyser(enJSON(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) == 0 {
		t.Fatal("des problèmes étaient attendus")
	}
	rendu := inst.RenduVerification(problemes)
	if !strings.Contains(rendu, "Incohérences détectées :") {
		t.Errorf("les incohérences doivent être signalées :\n%s", rendu)
	}
	if !strings.Contains(rendu, "analyse.icap_url") {
		t.Errorf("le champ fautif doit être cité :\n%s", rendu)
	}
}

func TestPolitiqueJSONAllerRetour(t *testing.T) {
	inst := analyserSansProbleme(t, enJSON(t, configComplete()))
	p := inst.Politique()
	donnees, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	texte := string(donnees)
	for _, motif := range []string{`"instance"`, `"mode"`, `"identification"`, `"options"`, `"dimension"`, `"niveau"`, `"conforme_ii901"`, `"taille_max_octets"`} {
		if !strings.Contains(texte, motif) {
			t.Errorf("clé %s absente du JSON : %s", motif, texte)
		}
	}
	var relu Politique
	if err := json.Unmarshal(donnees, &relu); err != nil {
		t.Fatal(err)
	}
	if len(relu.Options) != 9 {
		t.Errorf("9 options attendues, obtenu %d", len(relu.Options))
	}
	if relu.Instance != p.Instance || relu.TailleMaxOctets != p.TailleMaxOctets {
		t.Errorf("aller-retour infidèle : %+v", relu)
	}
	// La politique annonce le mécanisme d'identification : le client en a
	// besoin avant toute opération (matériel à présenter, en-têtes AUTH-4).
	if relu.Identification != "mtls" {
		t.Errorf("identification = %q, attendu « mtls »", relu.Identification)
	}
}

func TestDestinatairesAdmissibles(t *testing.T) {
	// Sous identification déclarative, la désignation de destinataires est
	// structurellement refusée : l'identité annoncée est falsifiable.
	inst := analyserSansProbleme(t, enJSON(t, configComplete()))
	if !inst.DestinatairesAdmissibles() {
		t.Error("mtls : la désignation de destinataires doit rester admissible")
	}
	m := configComplete()
	m["auth"]["mecanisme"] = "declaratif"
	m["auth"]["ac_clients"] = ""
	if analyserSansProbleme(t, enJSON(t, m)).DestinatairesAdmissibles() {
		t.Error("declaratif : la désignation de destinataires doit être refusée")
	}
}

func TestPadDroite(t *testing.T) {
	if obtenu := padDroite("Durée de vie", 17); len([]rune(obtenu)) != 17 {
		t.Errorf("padDroite doit compter en runes, obtenu %q", obtenu)
	}
	if obtenu := padDroite("trop-long-pour-la-colonne", 5); obtenu != "trop-long-pour-la-colonne" {
		t.Errorf("padDroite ne doit pas tronquer, obtenu %q", obtenu)
	}
}
