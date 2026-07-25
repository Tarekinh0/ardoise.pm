package store

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// collecteurDestructions enregistre les notifications de destruction.
type collecteurDestructions struct {
	mu     sync.Mutex
	notifs []string // "id:cause"
}

func (c *collecteurDestructions) rappel(id, empreinte, cause string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifs = append(c.notifs, id+":"+cause)
}

func (c *collecteurDestructions) liste() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.notifs...)
}

func ardoiseDeNotification(id string, echeance time.Time, lectureUnique bool) *Ardoise {
	return &Ardoise{
		ID:            id,
		Chiffre:       []byte{0x01, 0x02},
		Empreinte:     "cafe",
		Echeance:      echeance,
		LectureUnique: lectureUnique,
	}
}

// TestNotificationDestructionMemoire : lecture unique, expiration paresseuse
// et balayage notifient chacun leur cause, hors verrou, une seule fois.
func TestNotificationDestructionMemoire(t *testing.T) {
	magasin := NouveauMemoire(context.Background(), time.Hour)
	defer magasin.Fermer()
	collecteur := &collecteurDestructions{}
	magasin.DefinirRappelDestruction(collecteur.rappel)

	// Destruction à la première lecture.
	if err := magasin.Deposer(ardoiseDeNotification("aaaaaaaaaaaa", time.Now().Add(time.Hour), true)); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}

	// Expiration paresseuse à la lecture.
	if err := magasin.Deposer(ardoiseDeNotification("bbbbbbbbbbbb", time.Now().Add(-time.Second), false)); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("bbbbbbbbbbbb"); err != ErrIntrouvable {
		t.Fatalf("err = %v, attendu ErrIntrouvable", err)
	}

	// Balayage périodique.
	if err := magasin.Deposer(ardoiseDeNotification("cccccccccccc", time.Now().Add(-time.Second), false)); err != nil {
		t.Fatal(err)
	}
	magasin.purgerExpirees()

	// Une lecture sans destruction ne notifie rien.
	if err := magasin.Deposer(ardoiseDeNotification("dddddddddddd", time.Now().Add(time.Hour), false)); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("dddddddddddd"); err != nil {
		t.Fatal(err)
	}

	attendu := []string{
		"aaaaaaaaaaaa:" + DestructionLecture,
		"bbbbbbbbbbbb:" + DestructionEcheance,
		"cccccccccccc:" + DestructionEcheance,
	}
	obtenu := collecteur.liste()
	if len(obtenu) != len(attendu) {
		t.Fatalf("notifications = %v, attendu %v", obtenu, attendu)
	}
	for i := range attendu {
		if obtenu[i] != attendu[i] {
			t.Fatalf("notifications = %v, attendu %v", obtenu, attendu)
		}
	}
}

// TestNotificationDestructionDisque : mêmes causes sur le magasin disque.
func TestNotificationDestructionDisque(t *testing.T) {
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	magasin, err := NouveauDisque(context.Background(), t.TempDir(), cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer magasin.Fermer()
	collecteur := &collecteurDestructions{}
	magasin.DefinirRappelDestruction(collecteur.rappel)

	if err := magasin.Deposer(ardoiseDeNotification("aaaaaaaaaaaa", time.Now().Add(time.Hour), true)); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := magasin.Deposer(ardoiseDeNotification("bbbbbbbbbbbb", time.Now().Add(-time.Second), false)); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("bbbbbbbbbbbb"); err != ErrIntrouvable {
		t.Fatalf("err = %v, attendu ErrIntrouvable", err)
	}
	if err := magasin.Deposer(ardoiseDeNotification("cccccccccccc", time.Now().Add(-time.Second), false)); err != nil {
		t.Fatal(err)
	}
	magasin.purgerExpirees()

	attendu := []string{
		"aaaaaaaaaaaa:" + DestructionLecture,
		"bbbbbbbbbbbb:" + DestructionEcheance,
		"cccccccccccc:" + DestructionEcheance,
	}
	obtenu := collecteur.liste()
	if len(obtenu) != len(attendu) {
		t.Fatalf("notifications = %v, attendu %v", obtenu, attendu)
	}
	for i := range attendu {
		if obtenu[i] != attendu[i] {
			t.Fatalf("notifications = %v, attendu %v", obtenu, attendu)
		}
	}
}
