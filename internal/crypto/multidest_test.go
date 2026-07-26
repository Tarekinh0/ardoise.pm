package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// destinataireDeTest génère une paire X25519 et retourne le destinataire
// (identité + clé publique) et sa clé privée.
func destinataireDeTest(t *testing.T, identite string) (DestinataireMD, []byte) {
	t.Helper()
	privee, publique, err := GenererClePriveeMD()
	if err != nil {
		t.Fatal(err)
	}
	return DestinataireMD{Identite: identite, ClePublique: publique}, privee
}

func TestMultiDestFormat(t *testing.T) {
	alice, _ := destinataireDeTest(t, "alice.durand")
	bruno, _ := destinataireDeTest(t, "bruno.marchal")
	clair := []byte("contenu pour deux destinataires")

	chiffre, err := ChiffrerMultiDest(clair, []DestinataireMD{alice, bruno})
	if err != nil {
		t.Fatal(err)
	}
	if chiffre[0] != VersionMultiDest {
		t.Fatalf("octet de version = 0x%02x, attendu 0x05", chiffre[0])
	}
	if chiffre[1] != 2 {
		t.Fatalf("compteur = %d, attendu 2", chiffre[1])
	}
	// Taille : 2 (version+compteur) + 2×108 (entrées) + 12 (nonce) +
	// clair + 16 (étiquette GCM).
	attendue := 2 + 2*TailleEntreeMD + TailleNonce + len(clair) + 16
	if len(chiffre) != attendue {
		t.Fatalf("taille = %d, attendue %d", len(chiffre), attendue)
	}
	// L'empreinte d'identité de la première entrée est celle d'alice.
	if !bytes.Equal(chiffre[2:2+tailleEmpreinteIdentite], EmpreinteIdentiteMD("alice.durand")) {
		t.Error("empreinte d'identité de la première entrée inattendue")
	}
	// Le schéma est reconnu par Schema, sans clé ni mot de passe requis.
	schema, err := Schema(chiffre)
	if err != nil || schema != VersionMultiDest {
		t.Fatalf("Schema = 0x%02x, %v", schema, err)
	}
	if BesoinCle(schema) || BesoinMots(schema) {
		t.Error("CHIF-MD n'exige ni fragment de clé ni mot de passe")
	}
	if !EstMultiDest(schema) {
		t.Error("EstMultiDest doit reconnaître 0x05")
	}
	// Le clair ne figure jamais dans le chiffré.
	if bytes.Contains(chiffre, clair) {
		t.Error("le clair apparaît dans le chiffré")
	}
}

func TestMultiDestChaqueDestinataireOuvre(t *testing.T) {
	alice, priveeAlice := destinataireDeTest(t, "alice.durand")
	bruno, priveeBruno := destinataireDeTest(t, "bruno.marchal")
	clair := []byte("chacun ouvre avec sa propre clé")

	chiffre, err := ChiffrerMultiDest(clair, []DestinataireMD{alice, bruno})
	if err != nil {
		t.Fatal(err)
	}
	for nom, cas := range map[string]struct {
		identite string
		privee   []byte
	}{
		"alice par empreinte": {"alice.durand", priveeAlice},
		"bruno par empreinte": {"bruno.marchal", priveeBruno},
		"alice sans identité": {"", priveeAlice},
		"bruno sans identité": {"", priveeBruno},
	} {
		obtenu, err := DechiffrerMultiDest(chiffre, cas.identite, cas.privee)
		if err != nil {
			t.Errorf("%s : %v", nom, err)
			continue
		}
		if !bytes.Equal(obtenu, clair) {
			t.Errorf("%s : clair inattendu", nom)
		}
	}
}

func TestMultiDestNonDestinataireEchoue(t *testing.T) {
	alice, _ := destinataireDeTest(t, "alice.durand")
	_, priveeMallory := destinataireDeTest(t, "mallory")

	chiffre, err := ChiffrerMultiDest([]byte("réservé à alice"), []DestinataireMD{alice})
	if err != nil {
		t.Fatal(err)
	}
	// Mallory avec sa propre clé, avec ou sans identité annoncée.
	for _, identite := range []string{"", "mallory", "alice.durand"} {
		if _, err := DechiffrerMultiDest(chiffre, identite, priveeMallory); !errors.Is(err, ErrDechiffrement) {
			t.Errorf("identité %q : err = %v, attendu ErrDechiffrement", identite, err)
		}
	}
}

func TestMultiDestAlterations(t *testing.T) {
	alice, priveeAlice := destinataireDeTest(t, "alice.durand")
	bruno, _ := destinataireDeTest(t, "bruno.marchal")
	clair := []byte("intégrité de la table")

	chiffre, err := ChiffrerMultiDest(clair, []DestinataireMD{alice, bruno})
	if err != nil {
		t.Fatal(err)
	}
	alterer := func(position int) []byte {
		copie := append([]byte(nil), chiffre...)
		copie[position] ^= 0x01
		return copie
	}
	cas := map[string]int{
		"compteur":                     1,
		"empreinte d'identité (alice)": 2,
		"clé éphémère (alice)":         2 + tailleEmpreinteIdentite,
		"enveloppe (alice)":            2 + tailleEmpreinteIdentite + tailleClePubliqueMD + TailleNonce,
		"entrée de bruno":              2 + TailleEntreeMD + 3,
		"corps scellé":                 len(chiffre) - 1,
	}
	for nom, position := range cas {
		if _, err := DechiffrerMultiDest(alterer(position), "alice.durand", priveeAlice); !errors.Is(err, ErrDechiffrement) {
			t.Errorf("altération %s : err = %v, attendu ErrDechiffrement", nom, err)
		}
	}
	// Table tronquée (entrée retirée) : le compteur ne correspond plus.
	tronque := append([]byte(nil), chiffre[:2]...)
	tronque = append(tronque, chiffre[2+TailleEntreeMD:]...)
	if _, err := DechiffrerMultiDest(tronque, "bruno.marchal", priveeAlice); !errors.Is(err, ErrDechiffrement) {
		t.Errorf("table tronquée : err = %v, attendu ErrDechiffrement", err)
	}
}

func TestMultiDestBornes(t *testing.T) {
	alice, _ := destinataireDeTest(t, "alice.durand")
	if _, err := ChiffrerMultiDest([]byte("x"), nil); err == nil {
		t.Error("aucun destinataire : erreur attendue")
	}
	trop := make([]DestinataireMD, MaxDestinatairesMD+1)
	for i := range trop {
		trop[i] = alice
	}
	if _, err := ChiffrerMultiDest([]byte("x"), trop); err == nil {
		t.Error("au-delà de MaxDestinatairesMD : erreur attendue")
	}
	if _, err := ChiffrerMultiDest([]byte("x"), []DestinataireMD{{Identite: "a", ClePublique: []byte{1, 2}}}); err == nil {
		t.Error("clé publique invalide : erreur attendue")
	}
	// Chiffré tronqué et version étrangère.
	if _, err := DechiffrerMultiDest([]byte{VersionMultiDest}, "", make([]byte, 32)); !errors.Is(err, ErrDechiffrement) {
		t.Errorf("chiffré tronqué : %v", err)
	}
	if _, err := DechiffrerMultiDest([]byte{VersionCle, 1, 2, 3}, "", make([]byte, 32)); !errors.Is(err, ErrDechiffrement) {
		t.Errorf("version étrangère : %v", err)
	}
}

func TestMultiDestDechiffrerRefuse(t *testing.T) {
	// Le déchiffrement générique refuse le format CHIF-MD avec un message
	// orientant vers la clé privée de destinataire.
	alice, _ := destinataireDeTest(t, "alice.durand")
	chiffre, err := ChiffrerMultiDest([]byte("x"), []DestinataireMD{alice})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Dechiffrer(chiffre, make([]byte, TailleCle)); err == nil {
		t.Fatal("Dechiffrer doit refuser un chiffré CHIF-MD")
	}
}

func TestMultiDestIdentifiantSentinelle(t *testing.T) {
	identifiant := FormatIdentifiantMultiDest("abcdefgh2345")
	if identifiant != "abcdefgh2345#md" {
		t.Fatalf("identifiant = %q", identifiant)
	}
	id, cle, err := ParseIdentifiant(identifiant)
	if err != nil {
		t.Fatal(err)
	}
	if id != "abcdefgh2345" || cle != nil {
		t.Fatalf("id = %q, cle = %v : la sentinelle ne porte aucune clé", id, cle)
	}
}

func TestClePubliqueMD(t *testing.T) {
	privee, publique, err := GenererClePriveeMD()
	if err != nil {
		t.Fatal(err)
	}
	if len(privee) != 32 || len(publique) != 32 {
		t.Fatalf("tailles : privée %d, publique %d", len(privee), len(publique))
	}
	derivee, err := ClePubliqueMD(privee)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derivee, publique) {
		t.Error("la clé publique dérivée ne correspond pas")
	}
	if _, err := ClePubliqueMD([]byte{1, 2, 3}); err == nil {
		t.Error("clé privée invalide : erreur attendue")
	}
}
