package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// magasinsDeTest retourne les deux supports du produit, pour que chaque cas
// s'applique au contrat commun.
func magasinsDeTest(t *testing.T) map[string]Magasin {
	t.Helper()
	memoire := NouveauMemoire(context.Background(), time.Hour)
	t.Cleanup(func() { memoire.Fermer() })
	cle := make([]byte, 32)
	disque, err := NouveauDisque(context.Background(), filepath.Join(t.TempDir(), "magasin"), cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disque.Fermer() })
	return map[string]Magasin{"memoire": memoire, "disque": disque}
}

func TestPourPersiste(t *testing.T) {
	for nom, magasin := range magasinsDeTest(t) {
		t.Run(nom, func(t *testing.T) {
			a := &Ardoise{
				ID:       "abcdefgh2345",
				Chiffre:  []byte{0x01, 0x02},
				Echeance: time.Now().Add(time.Hour),
				Pour:     []string{"alice.durand", "@equipe-reseau"},
			}
			if err := magasin.Deposer(a); err != nil {
				t.Fatal(err)
			}
			relue, err := magasin.Recuperer("abcdefgh2345")
			if err != nil {
				t.Fatal(err)
			}
			if len(relue.Pour) != 2 || relue.Pour[0] != "alice.durand" || relue.Pour[1] != "@equipe-reseau" {
				t.Errorf("Pour = %v", relue.Pour)
			}
		})
	}
}

func TestRecupererSiRefuseSansConsommer(t *testing.T) {
	// Le prédicat est évalué AVANT la consommation : un lecteur refusé ne
	// détruit pas une ardoise à lecture unique, qui reste servable ensuite.
	for nom, magasin := range magasinsDeTest(t) {
		t.Run(nom, func(t *testing.T) {
			a := &Ardoise{
				ID:            "abcdefgh2345",
				Chiffre:       []byte{0x01},
				Echeance:      time.Now().Add(time.Hour),
				LectureUnique: true,
				Pour:          []string{"alice.durand"},
			}
			if err := magasin.Deposer(a); err != nil {
				t.Fatal(err)
			}
			refuse := func(*Ardoise) bool { return false }
			if _, err := magasin.RecupererSi("abcdefgh2345", refuse); !errors.Is(err, ErrNonAdmis) {
				t.Fatalf("prédicat refusant : err = %v, attendu ErrNonAdmis", err)
			}
			// L'ardoise n'a pas été consommée : un lecteur admis l'obtient.
			admis := func(a *Ardoise) bool { return len(a.Pour) == 1 && a.Pour[0] == "alice.durand" }
			if _, err := magasin.RecupererSi("abcdefgh2345", admis); err != nil {
				t.Fatalf("lecteur admis après refus : %v", err)
			}
			// Lecture unique : elle est maintenant consommée.
			if _, err := magasin.RecupererSi("abcdefgh2345", admis); !errors.Is(err, ErrIntrouvable) {
				t.Fatalf("après consommation : %v", err)
			}
		})
	}
}

func TestRecupererSiExpirationAvantPredicat(t *testing.T) {
	// L'expiration paresseuse précède le prédicat : une ardoise expirée
	// répond ErrIntrouvable, jamais ErrNonAdmis — l'échéance vaut pour tous.
	for nom, magasin := range magasinsDeTest(t) {
		t.Run(nom, func(t *testing.T) {
			a := &Ardoise{
				ID:       "abcdefgh2345",
				Chiffre:  []byte{0x01},
				Echeance: time.Now().Add(-time.Minute),
				Pour:     []string{"alice.durand"},
			}
			if err := magasin.Deposer(a); err != nil {
				t.Fatal(err)
			}
			refuse := func(*Ardoise) bool { return false }
			if _, err := magasin.RecupererSi("abcdefgh2345", refuse); !errors.Is(err, ErrIntrouvable) {
				t.Fatalf("ardoise expirée : err = %v, attendu ErrIntrouvable", err)
			}
		})
	}
}
