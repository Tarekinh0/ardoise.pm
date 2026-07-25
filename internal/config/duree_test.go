package config

import (
	"testing"
	"time"
)

func TestParseDuree(t *testing.T) {
	cas := []struct {
		entree  string
		attendu time.Duration
		erreur  bool
	}{
		{"30m", 30 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"168h", 168 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"90s", 90 * time.Second, false},
		{" 10s ", 10 * time.Second, false},
		{"", 0, true},
		{"24", 0, true},
		{"-1h", 0, true},
		{"0s", 0, true},
		{"1.5h", 0, true},
		{"10ms", 0, true},
		{"1j", 0, true},
		{"7d", 0, true},
		{"1h bidule", 0, true},
	}
	for _, c := range cas {
		t.Run(c.entree, func(t *testing.T) {
			d, err := ParseDuree(c.entree)
			if c.erreur {
				if err == nil {
					t.Fatalf("ParseDuree(%q) : erreur attendue, obtenu %v", c.entree, d)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDuree(%q) : erreur inattendue %v", c.entree, err)
			}
			if d != c.attendu {
				t.Fatalf("ParseDuree(%q) = %v, attendu %v", c.entree, d, c.attendu)
			}
		})
	}
}

func TestFormatDuree(t *testing.T) {
	cas := []struct {
		entree  time.Duration
		attendu string
	}{
		{time.Hour, "1h"},
		{90 * time.Minute, "1h30m"},
		{24 * time.Hour, "24h"},
		{168 * time.Hour, "168h"},
		{30 * time.Second, "30s"},
		{time.Hour + time.Minute + time.Second, "1h1m1s"},
		{0, "0s"},
		{-time.Hour, "0s"},
	}
	for _, c := range cas {
		if obtenu := FormatDuree(c.entree); obtenu != c.attendu {
			t.Errorf("FormatDuree(%v) = %q, attendu %q", c.entree, obtenu, c.attendu)
		}
	}
}

func TestParseFormatDureeAllerRetour(t *testing.T) {
	for _, texte := range []string{"30m", "2h", "24h", "1h30m", "45s"} {
		d, err := ParseDuree(texte)
		if err != nil {
			t.Fatalf("ParseDuree(%q) : %v", texte, err)
		}
		if obtenu := FormatDuree(d); obtenu != texte {
			t.Errorf("aller-retour %q → %q", texte, obtenu)
		}
	}
}

// TestRoundTripDureeExhaustif vérifie que chaque combinaison
// heure/minute/seconde admissible (0-168h, 0-59m, 0-59s, durée positive)
// survit à l'aller-retour ParseDuree → FormatDuree. Le test couvre toutes
// les valeurs intermédiaires, pas seulement quelques points choisis.
// PR-104 : le round-trip FormatDuree → ParseDuree était fragile —
// ce test exhaustif garantit la stabilité du format.
func TestRoundTripDureeExhaustif(t *testing.T) {
	heures := []int{0, 1, 2, 6, 12, 24, 48, 72, 168}
	minutes := []int{0, 1, 5, 15, 30, 45, 59}
	secondes := []int{0, 1, 10, 30, 59}

	for _, h := range heures {
		for _, m := range minutes {
			for _, s := range secondes {
				if h == 0 && m == 0 && s == 0 {
					continue
				}
				d := time.Duration(h)*time.Hour +
					time.Duration(m)*time.Minute +
					time.Duration(s)*time.Second
				formatee := FormatDuree(d)
				reparse, err := ParseDuree(formatee)
				if err != nil {
					t.Errorf("FormatDuree(%v) = %q → ParseDuree(%q) : %v", d, formatee, formatee, err)
					continue
				}
				if reparse != d {
					t.Errorf("round-trip %v → %q → %v : écart", d, formatee, reparse)
				}
			}
		}
	}
}
