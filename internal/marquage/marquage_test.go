package marquage

import (
	"bytes"
	"testing"
)

func TestEnTete(t *testing.T) {
	cas := []struct {
		nom, libelle, complement, attendu string
	}{
		{"libellé seul", "DIFFUSION RESTREINTE", "", "=== DIFFUSION RESTREINTE ===\n"},
		{"libellé et complément", "DIFFUSION RESTREINTE", "incident 4712", "=== DIFFUSION RESTREINTE — incident 4712 ===\n"},
		{"sans libellé", "", "complément orphelin", ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if obtenu := EnTete(c.libelle, c.complement); obtenu != c.attendu {
				t.Fatalf("EnTete = %q, attendu %q", obtenu, c.attendu)
			}
		})
	}
}

func TestAppliquer(t *testing.T) {
	contenu := []byte("ligne 1\nligne 2\n")

	marque := Appliquer("DIFFUSION RESTREINTE", "incident 4712", contenu)
	attendu := "=== DIFFUSION RESTREINTE — incident 4712 ===\nligne 1\nligne 2\n"
	if string(marque) != attendu {
		t.Fatalf("Appliquer = %q, attendu %q", marque, attendu)
	}
	// Le contenu d'origine n'est jamais modifié, seulement préfixé.
	if !bytes.Equal(contenu, []byte("ligne 1\nligne 2\n")) {
		t.Fatal("le contenu d'origine a été modifié")
	}
	if !bytes.HasSuffix(marque, contenu) {
		t.Fatal("le contenu ne suit pas l'en-tête à l'identique")
	}

	// MARQ-2 côté appelant : libellé vide, rien n'est préfixé.
	if intact := Appliquer("", "complément", contenu); !bytes.Equal(intact, contenu) {
		t.Fatalf("sans libellé, le contenu doit rester intact : %q", intact)
	}
}
