package secrets

import (
	"sync"
	"testing"
)

func moteurComplet(maxInputBytes int) *Engine {
	return NewEngine(maxInputBytes,
		NewPrivateKeyRecognizer(),
		NewJWTRecognizer(),
		NewSecretPrefixRecognizer(),
		NewSecretEntropyRecognizer(),
	)
}

func TestEngineInputTooLarge(t *testing.T) {
	e := moteurComplet(10)
	_, err := e.Detect("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err == nil || !IsInputTooLarge(err) {
		t.Fatalf("attendu ErrInputTooLarge, obtenu %v", err)
	}
}

func TestEngineNoRecognizers(t *testing.T) {
	e := NewEngine(0)
	entites, err := e.Detect("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil || entites != nil {
		t.Fatalf("moteur vide : entites=%v err=%v", entites, err)
	}
}

func TestEngineDetectsAndSorts(t *testing.T) {
	texte := "clé api_key=Zk9pQ2xVbTdSNGpXOHNMcUB3 puis jeton ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
	e := moteurComplet(0)
	entites, err := e.Detect(texte)
	if err != nil {
		t.Fatal(err)
	}
	if len(entites) < 2 {
		t.Fatalf("au moins 2 entités attendues, obtenu %d : %v", len(entites), entites)
	}
	for i := 1; i < len(entites); i++ {
		if entites[i-1].Start > entites[i].Start {
			t.Errorf("entités non triées par position : %v", entites)
		}
	}
}

func TestEngineEmptyInput(t *testing.T) {
	e := moteurComplet(0)
	entites, err := e.Detect("")
	if err != nil || len(entites) != 0 {
		t.Fatalf("entrée vide : entites=%v err=%v", entites, err)
	}
}

func TestEngineConcurrentUse(t *testing.T) {
	// Le moteur est annoncé sûr en usage concurrent : vérifié sous -race.
	e := moteurComplet(0)
	texte := "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Detect(texte); err != nil {
				t.Errorf("Detect : %v", err)
			}
		}()
	}
	wg.Wait()
}
