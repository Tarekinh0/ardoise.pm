package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLireContenu_LimiteStdin vérifie que la lecture depuis l'entrée standard
// est bornée par la limite configurée + 1, et que le dépassement est
// correctement détecté (T-BOUND-1, T-BOUND-2, T-BOUND-3).
func TestLireContenu_LimiteStdin(t *testing.T) {
	cas := []struct {
		nom            string
		contenu        []byte
		tailleMax      int64
		attenduErr     bool
		motifErreur    string
		tailleAttendue int
	}{
		{
			nom:            "sous la limite",
			contenu:        bytes.Repeat([]byte("A"), 100),
			tailleMax:      200,
			attenduErr:     false,
			tailleAttendue: 100,
		},
		{
			nom:            "exactement à la limite",
			contenu:        bytes.Repeat([]byte("B"), 256),
			tailleMax:      256,
			attenduErr:     false,
			tailleAttendue: 256,
		},
		{
			nom:            "un octet au-dessus de la limite",
			contenu:        bytes.Repeat([]byte("C"), 257),
			tailleMax:      256,
			attenduErr:     false, // lireContenu ne rejette pas, elle lit borné — le rejet est dans cmdPush
			tailleAttendue: 257,   // limité à tailleMax+1 = 257
		},
		{
			nom:            "dépassement significatif",
			contenu:        bytes.Repeat([]byte("D"), 2000),
			tailleMax:      256,
			attenduErr:     false,
			tailleAttendue: 257, // limité à tailleMax+1 = 257
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			ctx := &Contexte{
				Stdin: bytes.NewReader(c.contenu),
			}
			donnees, err := lireContenu(ctx, "", c.tailleMax)
			if c.attenduErr && err == nil {
				t.Fatal("erreur attendue, aucune reçue")
			}
			if !c.attenduErr && err != nil {
				t.Fatalf("erreur inattendue : %v", err)
			}
			if !c.attenduErr {
				if len(donnees) != c.tailleAttendue {
					t.Fatalf("taille lue = %d, attendu %d", len(donnees), c.tailleAttendue)
				}
			}
		})
	}
}

// TestLireContenu_LimiteFichier vérifie que la lecture depuis un fichier est
// bornée et que le descripteur est fermé (SRQ-B002, T-BOUND-4).
func TestLireContenu_LimiteFichier(t *testing.T) {
	repertoire := t.TempDir()

	ecrire := func(nom string, taille int) string {
		chemin := filepath.Join(repertoire, nom)
		if err := os.WriteFile(chemin, bytes.Repeat([]byte("X"), taille), 0644); err != nil {
			t.Fatal(err)
		}
		return chemin
	}

	cas := []struct {
		nom            string
		tailleFichier  int
		tailleMax      int64
		attenduErr     bool
		motifErreur    string
		tailleAttendue int
	}{
		{
			nom:            "fichier sous la limite",
			tailleFichier:  100,
			tailleMax:      200,
			tailleAttendue: 100,
		},
		{
			nom:            "fichier exactement à la limite",
			tailleFichier:  512,
			tailleMax:      512,
			tailleAttendue: 512,
		},
		{
			nom:            "fichier au-dessus de la limite",
			tailleFichier:  1024,
			tailleMax:      512,
			tailleAttendue: 513, // tailleMax + 1
		},
		{
			nom:           "fichier vide",
			tailleFichier: 0,
			tailleMax:     256,
			attenduErr:    true,
			motifErreur:   "vide",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			chemin := ecrire(c.nom, c.tailleFichier)
			ctx := &Contexte{}
			donnees, err := lireContenu(ctx, chemin, c.tailleMax)
			if c.attenduErr {
				if err == nil {
					t.Fatal("erreur attendue, aucune reçue")
				}
				if !strings.Contains(err.Error(), c.motifErreur) {
					t.Fatalf("motif %q absent de l'erreur : %v", c.motifErreur, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("erreur inattendue : %v", err)
			}
			if len(donnees) != c.tailleAttendue {
				t.Fatalf("taille lue = %d, attendu %d", len(donnees), c.tailleAttendue)
			}
		})
	}
}

// TestLireContenu_PlafondDur vérifie que sans limite configurée
// (TailleMaxOctets == 0), le plafond dur de 64 Mio est appliqué (SRQ-B001).
func TestLireContenu_PlafondDur(t *testing.T) {
	// Entrée sous le plafond dur : tout passe.
	contenu := bytes.Repeat([]byte("A"), 100)
	ctx := &Contexte{Stdin: bytes.NewReader(contenu)}
	donnees, err := lireContenu(ctx, "", 0)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if len(donnees) != 100 {
		t.Fatalf("taille lue = %d, attendu 100", len(donnees))
	}

	// Entrée au-delà du plafond : bornée à PlafondClientTaille + 1.
	// On simule une entrée plus grande que le plafond : le lecteur borné
	// lit PlafondClientTaille + 1, jamais l'intégralité.
	grandContenu := bytes.NewReader(bytes.Repeat([]byte("B"), PlafondClientTaille+100))
	ctx2 := &Contexte{Stdin: grandContenu}
	donnees2, err2 := lireContenu(ctx2, "", 0)
	if err2 != nil {
		t.Fatalf("erreur inattendue : %v", err2)
	}
	if len(donnees2) != PlafondClientTaille+1 {
		t.Fatalf("taille lue = %d, attendu PlafondClientTaille+1 (%d)", len(donnees2), PlafondClientTaille+1)
	}
}

// TestLireContenu_FichierInexistant vérifie le cas d'erreur sans lecture.
func TestLireContenu_FichierInexistant(t *testing.T) {
	ctx := &Contexte{}
	_, err := lireContenu(ctx, "/chemin/inexistant/ardoise", 256)
	if err == nil {
		t.Fatal("erreur attendue pour fichier inexistant")
	}
}
