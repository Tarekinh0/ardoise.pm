package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// magasins liste les deux supports sous le même contrat, afin que chaque
// propriété du Magasin soit vérifiée sur les deux.
func magasins(t *testing.T) map[string]Magasin {
	t.Helper()
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	disque, err := NouveauDisque(context.Background(), t.TempDir(), cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	memoire := NouveauMemoire(context.Background(), time.Hour)
	t.Cleanup(func() { memoire.Fermer(); disque.Fermer() })
	return map[string]Magasin{"memoire": memoire, "disque": disque}
}

func ardoiseDeTest(id string, echeance time.Time, lectureUnique bool) *Ardoise {
	return &Ardoise{
		ID:                 id,
		Chiffre:            []byte("chiffré factice " + id),
		Empreinte:          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Echeance:           echeance,
		LectureUnique:      lectureUnique,
		MarquageComplement: "incident 42",
	}
}

func TestDepotEtRecuperation(t *testing.T) {
	for nom, magasin := range magasins(t) {
		t.Run(nom, func(t *testing.T) {
			depose := ardoiseDeTest("abcdefghij22", time.Now().Add(time.Hour), false)
			if err := magasin.Deposer(depose); err != nil {
				t.Fatal(err)
			}
			rendue, err := magasin.Recuperer("abcdefghij22")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rendue.Chiffre, depose.Chiffre) ||
				rendue.Empreinte != depose.Empreinte ||
				rendue.MarquageComplement != depose.MarquageComplement {
				t.Fatalf("ardoise rendue = %+v", rendue)
			}
			// Sans lecture unique, une seconde lecture sert encore.
			if _, err := magasin.Recuperer("abcdefghij22"); err != nil {
				t.Fatalf("seconde lecture : %v", err)
			}
		})
	}
}

func TestCollisionIdentifiant(t *testing.T) {
	for nom, magasin := range magasins(t) {
		t.Run(nom, func(t *testing.T) {
			a := ardoiseDeTest("abcdefghij23", time.Now().Add(time.Hour), false)
			if err := magasin.Deposer(a); err != nil {
				t.Fatal(err)
			}
			if err := magasin.Deposer(a); !errors.Is(err, ErrExiste) {
				t.Fatalf("erreur = %v, attendu ErrExiste", err)
			}
		})
	}
}

func TestAbsenteExpireeConsommeeIndistinguables(t *testing.T) {
	for nom, magasin := range magasins(t) {
		t.Run(nom, func(t *testing.T) {
			// Absente.
			_, errAbsente := magasin.Recuperer("abcdefghij24")

			// Expirée (expiration paresseuse, sans attendre le balayage).
			expiree := ardoiseDeTest("abcdefghij25", time.Now().Add(20*time.Millisecond), false)
			if err := magasin.Deposer(expiree); err != nil {
				t.Fatal(err)
			}
			time.Sleep(30 * time.Millisecond)
			_, errExpiree := magasin.Recuperer("abcdefghij25")

			// Consommée (lecture unique).
			consommee := ardoiseDeTest("abcdefghij26", time.Now().Add(time.Hour), true)
			if err := magasin.Deposer(consommee); err != nil {
				t.Fatal(err)
			}
			if _, err := magasin.Recuperer("abcdefghij26"); err != nil {
				t.Fatal(err)
			}
			_, errConsommee := magasin.Recuperer("abcdefghij26")

			for cas, err := range map[string]error{"absente": errAbsente, "expirée": errExpiree, "consommée": errConsommee} {
				if !errors.Is(err, ErrIntrouvable) {
					t.Errorf("%s : erreur = %v, attendu ErrIntrouvable", cas, err)
				}
			}
		})
	}
}

// TestLectureUniqueConcurrente vérifie l'atomicité de la consommation :
// parmi N lectures concurrentes d'une ardoise à lecture unique, exactement
// une obtient le contenu.
func TestLectureUniqueConcurrente(t *testing.T) {
	for nom, magasin := range magasins(t) {
		t.Run(nom, func(t *testing.T) {
			if err := magasin.Deposer(ardoiseDeTest("abcdefghij27", time.Now().Add(time.Hour), true)); err != nil {
				t.Fatal(err)
			}
			const lecteurs = 32
			var succes, introuvables atomic.Int32
			var pret, fini sync.WaitGroup
			depart := make(chan struct{})
			pret.Add(lecteurs)
			fini.Add(lecteurs)
			for i := 0; i < lecteurs; i++ {
				go func() {
					defer fini.Done()
					pret.Done()
					<-depart
					switch _, err := magasin.Recuperer("abcdefghij27"); {
					case err == nil:
						succes.Add(1)
					case errors.Is(err, ErrIntrouvable):
						introuvables.Add(1)
					default:
						t.Errorf("erreur inattendue : %v", err)
					}
				}()
			}
			pret.Wait()
			close(depart)
			fini.Wait()
			if succes.Load() != 1 || introuvables.Load() != lecteurs-1 {
				t.Fatalf("succès = %d, introuvables = %d : exactement une lecture doit servir",
					succes.Load(), introuvables.Load())
			}
		})
	}
}

// TestDepotsEtLecturesConcurrents fait travailler dépôts, lectures et
// balayage en parallèle ; la course est surveillée par -race.
func TestDepotsEtLecturesConcurrents(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	disque, err := NouveauDisque(context.Background(), t.TempDir(), cle, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	memoire := NouveauMemoire(context.Background(), 5*time.Millisecond)
	t.Cleanup(func() { memoire.Fermer(); disque.Fermer() })

	ids := []string{"aaaaaaaaaaa2", "aaaaaaaaaaa3", "aaaaaaaaaaa4", "aaaaaaaaaaa5"}
	for nom, magasin := range map[string]Magasin{"memoire": memoire, "disque": disque} {
		t.Run(nom, func(t *testing.T) {
			var fini sync.WaitGroup
			for _, id := range ids {
				fini.Add(2)
				go func() {
					defer fini.Done()
					// Échéances courtes : le balayage travaille pendant le test.
					a := ardoiseDeTest(id, time.Now().Add(10*time.Millisecond), false)
					if err := magasin.Deposer(a); err != nil && !errors.Is(err, ErrExiste) {
						t.Errorf("dépôt %s : %v", id, err)
					}
				}()
				go func() {
					defer fini.Done()
					for i := 0; i < 10; i++ {
						if _, err := magasin.Recuperer(id); err != nil && !errors.Is(err, ErrIntrouvable) {
							t.Errorf("lecture %s : %v", id, err)
						}
						time.Sleep(2 * time.Millisecond)
					}
				}()
			}
			fini.Wait()
		})
	}
}

func TestBalayageDetruitLesExpirees(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	rep := t.TempDir()
	disque, err := NouveauDisque(context.Background(), rep, cle, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	memoire := NouveauMemoire(context.Background(), 10*time.Millisecond)
	t.Cleanup(func() { memoire.Fermer(); disque.Fermer() })

	for _, magasin := range []Magasin{memoire, disque} {
		if err := magasin.Deposer(ardoiseDeTest("abcdefghij28", time.Now().Add(20*time.Millisecond), false)); err != nil {
			t.Fatal(err)
		}
	}
	// Le fichier de l'ardoise expirée doit disparaître du disque sans
	// qu'aucune lecture ne le touche (ADR-003 : le serveur garantit
	// l'expiration indépendamment de toute action client).
	chemin := filepath.Join(rep, "abcdefghij28"+extension)
	attente := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(chemin); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(attente) {
			t.Fatal("le balayage n'a pas détruit le fichier expiré")
		}
		time.Sleep(10 * time.Millisecond)
	}
	memoire.mu.RLock()
	_, presente := memoire.ardoises["abcdefghij28"]
	memoire.mu.RUnlock()
	if presente {
		t.Fatal("le balayage n'a pas purgé l'ardoise expirée de la mémoire")
	}
}

func TestBalayageStoppeSurAnnulationContexte(t *testing.T) {
	ctx, annuler := context.WithCancel(context.Background())
	memoire := NouveauMemoire(ctx, time.Millisecond)
	annuler()
	time.Sleep(20 * time.Millisecond)
	// Après l'annulation, le magasin reste utilisable : l'expiration
	// paresseuse continue de faire respecter l'échéance à la lecture.
	if err := memoire.Deposer(ardoiseDeTest("abcdefghij29", time.Now().Add(-time.Second), false)); err != nil {
		t.Fatal(err)
	}
	if _, err := memoire.Recuperer("abcdefghij29"); !errors.Is(err, ErrIntrouvable) {
		t.Fatalf("erreur = %v, attendu ErrIntrouvable", err)
	}
	memoire.Fermer()
}

func TestDisqueSurvitAuRedemarrage(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	rep := t.TempDir()

	premier, err := NouveauDisque(context.Background(), rep, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	depose := ardoiseDeTest("abcdefghij32", time.Now().Add(time.Hour), false)
	if err := premier.Deposer(depose); err != nil {
		t.Fatal(err)
	}
	premier.Fermer()

	// Nouvelle instance du magasin sur le même répertoire, même clé.
	second, err := NouveauDisque(context.Background(), rep, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Fermer()
	rendue, err := second.Recuperer("abcdefghij32")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendue.Chiffre, depose.Chiffre) || !rendue.Echeance.Equal(depose.Echeance) {
		t.Fatalf("ardoise rendue après redémarrage = %+v", rendue)
	}
}

func TestDisqueMauvaiseCleIntrouvable(t *testing.T) {
	bonne := make([]byte, 32)
	if _, err := rand.Read(bonne); err != nil {
		t.Fatal(err)
	}
	rep := t.TempDir()
	premier, err := NouveauDisque(context.Background(), rep, bonne, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := premier.Deposer(ardoiseDeTest("abcdefghij33", time.Now().Add(time.Hour), false)); err != nil {
		t.Fatal(err)
	}
	premier.Fermer()

	mauvaise := make([]byte, 32)
	second, err := NouveauDisque(context.Background(), rep, mauvaise, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Fermer()
	if _, err := second.Recuperer("abcdefghij33"); !errors.Is(err, ErrIntrouvable) {
		t.Fatalf("erreur = %v, attendu ErrIntrouvable", err)
	}
	// La clé erronée ne détruit pas l'enregistrement : le fichier survit.
	if _, err := os.Lstat(filepath.Join(rep, "abcdefghij33"+extension)); err != nil {
		t.Fatalf("le fichier ne doit pas être détruit par une clé erronée : %v", err)
	}
}

func TestDisqueFichierCorrompuIntrouvable(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	rep := t.TempDir()
	disque, err := NouveauDisque(context.Background(), rep, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer disque.Fermer()
	if err := disque.Deposer(ardoiseDeTest("abcdefghij34", time.Now().Add(time.Hour), false)); err != nil {
		t.Fatal(err)
	}
	chemin := filepath.Join(rep, "abcdefghij34"+extension)
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	donnees[len(donnees)-1] ^= 0x01
	if err := os.WriteFile(chemin, donnees, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := disque.Recuperer("abcdefghij34"); !errors.Is(err, ErrIntrouvable) {
		t.Fatalf("erreur = %v, attendu ErrIntrouvable", err)
	}
}

func TestDisqueJamaisDeClairSurLeSupport(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	rep := t.TempDir()
	disque, err := NouveauDisque(context.Background(), rep, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer disque.Fermer()
	a := ardoiseDeTest("abcdefghij35", time.Now().Add(time.Hour), false)
	if err := disque.Deposer(a); err != nil {
		t.Fatal(err)
	}
	donnees, err := os.ReadFile(filepath.Join(rep, "abcdefghij35"+extension))
	if err != nil {
		t.Fatal(err)
	}
	// Ni le contenu, ni l'empreinte, ni le complément de marquage ne
	// doivent apparaître en clair dans le fichier.
	for _, sensible := range [][]byte{a.Chiffre, []byte(a.Empreinte), []byte(a.MarquageComplement), []byte(`"id"`)} {
		if bytes.Contains(donnees, sensible) {
			t.Fatalf("le fichier du magasin contient %q en clair", sensible)
		}
	}
}

func TestDisqueRefuseIdentifiantMalsain(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	disque, err := NouveauDisque(context.Background(), t.TempDir(), cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer disque.Fermer()
	for _, id := range []string{"", "../evasion", "abc/def", "ABCDEF", "abcdefghij2\x00"} {
		if err := disque.Deposer(ardoiseDeTest(id, time.Now().Add(time.Hour), false)); err == nil {
			t.Errorf("dépôt accepté pour l'identifiant %q", id)
		}
		if _, err := disque.Recuperer(id); !errors.Is(err, ErrIntrouvable) {
			t.Errorf("lecture de %q : erreur = %v, attendu ErrIntrouvable", id, err)
		}
	}
}

func TestChargerCleMagasin(t *testing.T) {
	rep := t.TempDir()
	brute := make([]byte, 32)
	if _, err := rand.Read(brute); err != nil {
		t.Fatal(err)
	}

	cheminBrut := filepath.Join(rep, "brute.cle")
	if err := os.WriteFile(cheminBrut, brute, 0o600); err != nil {
		t.Fatal(err)
	}
	cle, err := ChargerCleMagasin(cheminBrut)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cle, brute) {
		t.Fatal("clé brute mal chargée")
	}

	cheminHex := filepath.Join(rep, "hex.cle")
	if err := os.WriteFile(cheminHex, []byte(hex.EncodeToString(brute)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cle, err = ChargerCleMagasin(cheminHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cle, brute) {
		t.Fatal("clé hexadécimale mal chargée")
	}

	cheminCourt := filepath.Join(rep, "courte.cle")
	if err := os.WriteFile(cheminCourt, []byte("trop courte"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerCleMagasin(cheminCourt); err == nil {
		t.Error("clé trop courte acceptée")
	}

	cheminOuvert := filepath.Join(rep, "ouverte.cle")
	if err := os.WriteFile(cheminOuvert, brute, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerCleMagasin(cheminOuvert); err == nil {
		t.Error("clé aux droits trop ouverts acceptée")
	}

	if _, err := ChargerCleMagasin(filepath.Join(rep, "absente.cle")); err == nil {
		t.Error("clé absente acceptée")
	}
}

func TestNouveauDisqueRefuseMauvaiseCle(t *testing.T) {
	if _, err := NouveauDisque(context.Background(), t.TempDir(), []byte("courte"), time.Hour); err == nil {
		t.Fatal("clé de magasin de mauvaise taille acceptée")
	}
}
