package crypto

import (
	"bytes"
	"testing"
)

// TestAllerRetourCHIF4 : le chiffré serveur (mode analysé) porte l'octet de
// version 0x04, se déchiffre avec la seule clé retournée, et suit la même
// disposition que CHIF-2 (version ‖ nonce ‖ scellé).
func TestAllerRetourCHIF4(t *testing.T) {
	clair := []byte("contenu analysé puis chiffré par le serveur")
	chiffre, cle, err := ChiffrerServeur(clair)
	if err != nil {
		t.Fatal(err)
	}
	if chiffre[0] != VersionServeur {
		t.Fatalf("octet de version = 0x%02x, attendu 0x%02x", chiffre[0], VersionServeur)
	}
	if len(cle) != TailleCle {
		t.Fatalf("clé de %d octets, attendu %d", len(cle), TailleCle)
	}
	if len(chiffre) != 1+TailleNonce+len(clair)+16 {
		t.Fatalf("chiffré de %d octets, attendu %d (version ‖ nonce ‖ scellé)",
			len(chiffre), 1+TailleNonce+len(clair)+16)
	}

	// Le format est auto-descriptif : le client de récupération n'a besoin
	// que du fragment de clé, comme pour CHIF-2.
	version, err := Schema(chiffre)
	if err != nil || version != VersionServeur {
		t.Fatalf("Schema = 0x%02x, %v", version, err)
	}
	if !BesoinCle(version) || BesoinMots(version) {
		t.Fatal("CHIF-4 exige la clé du fragment, jamais de mots")
	}

	rendu, err := Dechiffrer(chiffre, cle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendu, clair) {
		t.Fatalf("clair rendu = %q, attendu %q", rendu, clair)
	}

	// Mauvaise clé : refus indistinct (ErrDechiffrement).
	mauvaise := make([]byte, TailleCle)
	if _, err := Dechiffrer(chiffre, mauvaise); err != ErrDechiffrement {
		t.Fatalf("mauvaise clé : err = %v, attendu ErrDechiffrement", err)
	}

	// Altération du corps : refus.
	altere := append([]byte(nil), chiffre...)
	altere[len(altere)-1] ^= 0x01
	if _, err := Dechiffrer(altere, cle); err != ErrDechiffrement {
		t.Fatalf("altération : err = %v, attendu ErrDechiffrement", err)
	}

	// Altération de l'octet de version (couvert par l'AAD) : refus.
	usurpe := append([]byte(nil), chiffre...)
	usurpe[0] = VersionCle
	if _, err := Dechiffrer(usurpe, cle); err != ErrDechiffrement {
		t.Fatalf("version substituée : err = %v, attendu ErrDechiffrement", err)
	}
}

// TestCHIF4ClesUniques : une clé fraîche par appel (usage unique, annexe B).
func TestCHIF4ClesUniques(t *testing.T) {
	_, cle1, err := ChiffrerServeur([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, cle2, err := ChiffrerServeur([]byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cle1, cle2) {
		t.Fatal("deux chiffrements ont produit la même clé")
	}
}
