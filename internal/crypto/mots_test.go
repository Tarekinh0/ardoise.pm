package crypto

import (
	"bytes"
	"testing"
)

// TestPRNGDeterministe couvre prngDeterministe.Read : lectures multiples, déterminisme,
// graines différentes → sorties différentes, Read(nil), Read([]byte{}).
// PR-012
func TestPRNGDeterministe(t *testing.T) {
	t.Run("déterminisme", func(t *testing.T) {
		graine := []byte("graine-test-determinisme-v1")
		d1 := nouveauPRNGDeterministe(graine)
		d2 := nouveauPRNGDeterministe(graine)
		out1 := make([]byte, 64)
		out2 := make([]byte, 64)
		if _, err := d1.Read(out1); err != nil {
			t.Fatal(err)
		}
		if _, err := d2.Read(out2); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out1, out2) {
			t.Fatal("même graine → sorties différentes")
		}
	})

	t.Run("graines différentes", func(t *testing.T) {
		d1 := nouveauPRNGDeterministe([]byte("graine-A"))
		d2 := nouveauPRNGDeterministe([]byte("graine-B"))
		out1 := make([]byte, 32)
		out2 := make([]byte, 32)
		d1.Read(out1)
		d2.Read(out2)
		if bytes.Equal(out1, out2) {
			t.Fatal("graines différentes → même sortie")
		}
	})

	t.Run("lecture nulle", func(t *testing.T) {
		d := nouveauPRNGDeterministe([]byte("test-lecture-nulle"))
		n, err := d.Read(nil)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("Read(nil) a lu %d octets, attendu 0", n)
		}
	})

	t.Run("lecture vide", func(t *testing.T) {
		d := nouveauPRNGDeterministe([]byte("test-lecture-vide"))
		n, err := d.Read([]byte{})
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("Read([]byte{}) a lu %d octets, attendu 0", n)
		}
	})

	t.Run("lecture multi-blocs", func(t *testing.T) {
		d := nouveauPRNGDeterministe([]byte("test-multi-blocs"))
		// Chaque bloc fait 32 octets (SHA-256), on lit 80 octets → 3 blocs
		out := make([]byte, 80)
		if _, err := d.Read(out); err != nil {
			t.Fatal(err)
		}
		// Vérifier que les blocs ne sont pas identiques
		bloc1 := out[:32]
		bloc2 := out[32:64]
		if bytes.Equal(bloc1, bloc2) {
			t.Error("blocs consécutifs identiques — le DRBG ne progresse pas")
		}
	})

	t.Run("réapprovisionnement", func(t *testing.T) {
		graine := []byte("graine-reappro")
		d := nouveauPRNGDeterministe(graine)
		petit := make([]byte, 4)
		// Lire 4 octets → buf initial a 32, idx=4, il reste 28 octets
		d.Read(petit)
		// Lire 64 octets → force au moins un réapprovisionnement
		grand := make([]byte, 64)
		if _, err := d.Read(grand); err != nil {
			t.Fatal(err)
		}
		// Vérifier que la sortie n'est pas nulle (le DRBG fonctionne)
		zeros := make([]byte, 64)
		if bytes.Equal(grand, zeros) {
			t.Fatal("sortie DRBG entièrement nulle — suspect")
		}
	})
}

// TestChiffrerAvecCle couvre ChiffrerAvecCle pour VersionServeur
// et une version inconnue (PR-015).
func TestChiffrerAvecCle(t *testing.T) {
	cle := bytes.Repeat([]byte{0xaa}, TailleCle)
	blobSalt := bytes.Repeat([]byte{0xbb}, TailleBlobSalt)
	clair := []byte("test ChiffrerAvecCle")

	t.Run("VersionServeur sans sel", func(t *testing.T) {
		chiffre, err := ChiffrerAvecCle(VersionServeur, blobSalt, cle, clair)
		if err != nil {
			t.Fatal(err)
		}
		if chiffre[0] != VersionServeur {
			t.Fatalf("version = 0x%02x, attendu 0x%02x", chiffre[0], VersionServeur)
		}
		// VersionServeur ne produit pas de sel dans l'en-tête
		_, _, _, _, err = decouper(chiffre)
		if err != nil {
			t.Fatal(err)
		}
		// Déchiffrement aller-retour
		rendu, err := Dechiffrer(chiffre, cle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q, attendu %q", rendu, clair)
		}
	})

	t.Run("VersionMots avec sel", func(t *testing.T) {
		chiffre, err := ChiffrerAvecCle(VersionMots, blobSalt, cle, clair)
		if err != nil {
			t.Fatal(err)
		}
		if chiffre[0] != VersionMots {
			t.Fatalf("version = 0x%02x, attendu 0x%02x", chiffre[0], VersionMots)
		}
		_, sel, _, _, err := decouper(chiffre)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sel, blobSalt) {
			t.Fatalf("sel = %x, attendu %x", sel, blobSalt)
		}
	})

	t.Run("version inconnue", func(t *testing.T) {
		_, err := ChiffrerAvecCle(0xFF, blobSalt, cle, clair)
		if err == nil {
			t.Fatal("version inconnue non refusée par ChiffrerAvecCle")
		}
	})
}

// TestGenererMotsBorne vérifie la borne de n (PR-020) et le bon
// fonctionnement pour la valeur canonique n=5.
func TestGenererMotsBorne(t *testing.T) {
	_, err := GenererMots(0)
	if err == nil {
		t.Error("n=0 accepté")
	}
	_, err = GenererMots(-1)
	if err == nil {
		t.Error("n=-1 accepté")
	}
	_, err = GenererMots(9)
	if err == nil {
		t.Error("n=9 accepté")
	}
	mots, err := GenererMots(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(mots) != 5 {
		t.Fatalf("%d mots générés, attendu 5", len(mots))
	}
	if !MotsValides(mots) {
		t.Fatal("mots générés invalides")
	}
}

// TestDecouperMotsVersionInconnue vérifie que decouper traite correctement
// une version sans sel.
func TestDecouperMotsVersionInconnue(t *testing.T) {
	cle := bytes.Repeat([]byte{0xaa}, TailleCle)
	clair := []byte("test")
	// sceller accepte toute version sans validation ; seul Schema les rejette.
	// Ce test vérifie le comportement de decouper avec une version arbitraire.
	chiffre, err := sceller(0xFF, nil, cle, clair)
	if err != nil {
		t.Fatal(err)
	}
	_, sel, _, _, err := decouper(chiffre)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 0 {
		t.Fatalf("sel non nul pour version inconnue : %x", sel)
	}
}
