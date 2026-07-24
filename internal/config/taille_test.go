package config

import "testing"

func TestParseTaille(t *testing.T) {
	cas := []struct {
		entree  string
		attendu int64
		erreur  bool
	}{
		{"256Kio", 256 * 1024, false},
		{"256 Kio", 256 * 1024, false},
		{"1Mio", 1 << 20, false},
		{"512o", 512, false},
		{"1o", 1, false},
		{"", 0, true},
		{"256", 0, true},
		{"256Ko", 0, true},
		{"256kio", 0, true},
		{"-1Kio", 0, true},
		{"0Kio", 0, true},
		{"1.5Mio", 0, true},
		{"99999999999999999999Mio", 0, true},
		{"9999999999999Mio", 0, true},
	}
	for _, c := range cas {
		t.Run(c.entree, func(t *testing.T) {
			n, err := ParseTaille(c.entree)
			if c.erreur {
				if err == nil {
					t.Fatalf("ParseTaille(%q) : erreur attendue, obtenu %d", c.entree, n)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTaille(%q) : erreur inattendue %v", c.entree, err)
			}
			if n != c.attendu {
				t.Fatalf("ParseTaille(%q) = %d, attendu %d", c.entree, n, c.attendu)
			}
		})
	}
}

func TestFormatTaille(t *testing.T) {
	cas := []struct {
		entree  int64
		attendu string
	}{
		{256 * 1024, "256 Kio"},
		{1 << 20, "1 Mio"},
		{512, "512 o"},
		{1536, "1536 o"}, // 1,5 Kio : pas un multiple entier, reste en octets
		{0, "0 o"},
	}
	for _, c := range cas {
		if obtenu := FormatTaille(c.entree); obtenu != c.attendu {
			t.Errorf("FormatTaille(%d) = %q, attendu %q", c.entree, obtenu, c.attendu)
		}
	}
}
