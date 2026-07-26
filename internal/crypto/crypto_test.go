package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"
)

// TestVecteurAES256GCM ancre la chaîne AES-256-GCM sur un vecteur de test
// connu (NIST CAVP, AES-256, clair vide) : clé nulle, nonce nul, étiquette
// attendue 530f8afbc74536b9a963b4f1c4cb738b.
func TestVecteurAES256GCM(t *testing.T) {
	cle := make([]byte, TailleCle)
	nonce := make([]byte, TailleNonce)
	bloc, err := aes.NewCipher(cle)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(bloc)
	if err != nil {
		t.Fatal(err)
	}
	etiquette := gcm.Seal(nil, nonce, nil, nil)
	if attendu := "530f8afbc74536b9a963b4f1c4cb738b"; hex.EncodeToString(etiquette) != attendu {
		t.Fatalf("étiquette GCM = %x, attendu %s", etiquette, attendu)
	}
}

// TestVecteurFormatCHIF2 vérifie le format du chiffré CHIF-2.
func TestVecteurFormatCHIF2(t *testing.T) {
	cle := bytes.Repeat([]byte{0x42}, TailleCle)
	nonce := bytes.Repeat([]byte{0x24}, TailleNonce)
	clair := []byte("contenu de test ardoise")

	obtenu, err := scellerAvecNonce(VersionCle, nil, nonce, cle, clair)
	if err != nil {
		t.Fatal(err)
	}

	bloc, _ := aes.NewCipher(cle)
	gcm, _ := cipher.NewGCM(bloc)
	attendu := append([]byte{VersionCle}, nonce...)
	attendu = gcm.Seal(attendu, nonce, clair, []byte{VersionCle})
	if !bytes.Equal(obtenu, attendu) {
		t.Fatalf("chiffré = %x\nattendu   %x", obtenu, attendu)
	}

	rendu, err := Dechiffrer(obtenu, cle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendu, clair) {
		t.Fatalf("clair = %q", rendu)
	}
}

func TestParametresArgon2AnnexeB(t *testing.T) {
	if Argon2Memoire != 64*1024 {
		t.Errorf("mémoire Argon2id = %d Kio, l'annexe B impose 64 Mio", Argon2Memoire)
	}
	if Argon2Iterations != 3 {
		t.Errorf("itérations Argon2id = %d, l'annexe B impose 3", Argon2Iterations)
	}
	if Argon2Parallelisme != 4 {
		t.Errorf("parallélisme Argon2id = %d, l'annexe B impose 4", Argon2Parallelisme)
	}
	if TailleSel != 16 {
		t.Errorf("sel = %d octets, l'annexe B impose 128 bits", TailleSel)
	}
	if TailleCle != 32 {
		t.Errorf("clé = %d octets, l'annexe B impose 256 bits", TailleCle)
	}
	if TailleNonce != 12 {
		t.Errorf("nonce = %d octets, l'annexe B impose 96 bits", TailleNonce)
	}
}

func TestAllerRetourTousSchemas(t *testing.T) {
	clair := []byte("aller-retour sur tous les schémas de protection")

	t.Run("CHIF-2", func(t *testing.T) {
		chiffre, cle, err := ChiffrerCle(clair)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := Schema(chiffre); v != VersionCle || !BesoinCle(v) {
			t.Fatalf("schéma inattendu 0x%02x", v)
		}
		rendu, err := Dechiffrer(chiffre, cle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q", rendu)
		}
	})

	t.Run("CHIF-4", func(t *testing.T) {
		chiffre, cle, err := ChiffrerServeur(clair)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := Schema(chiffre); v != VersionServeur || !BesoinCle(v) {
			t.Fatalf("schéma inattendu 0x%02x", v)
		}
		rendu, err := Dechiffrer(chiffre, cle)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q", rendu)
		}
	})
}

// TestAlterationDetectee retourne chaque octet du chiffré un à un : toute
// altération doit faire échouer l'ouverture.
func TestAlterationDetectee(t *testing.T) {
	clair := []byte("intégrité")
	chiffre, cle, err := ChiffrerCle(clair)
	if err != nil {
		t.Fatal(err)
	}
	for i := range chiffre {
		altere := append([]byte(nil), chiffre...)
		altere[i] ^= 0x01
		if _, err := Dechiffrer(altere, cle); err == nil {
			t.Fatalf("altération de l'octet %d non détectée", i)
		}
	}
	if _, err := Dechiffrer(chiffre[:len(chiffre)-1], cle); err == nil {
		t.Fatal("troncature non détectée")
	}
}

func TestMauvaisMaterielRefuse(t *testing.T) {
	clair := []byte("secret")

	t.Run("mauvaise clé CHIF-2", func(t *testing.T) {
		chiffre, cle, err := ChiffrerCle(clair)
		if err != nil {
			t.Fatal(err)
		}
		mauvaise := append([]byte(nil), cle...)
		mauvaise[0] ^= 0xff
		if _, err := Dechiffrer(chiffre, mauvaise); err != ErrDechiffrement {
			t.Fatalf("erreur = %v, attendu ErrDechiffrement", err)
		}
	})
}

func TestClesEtNoncesUniques(t *testing.T) {
	clair := []byte("unicité")
	c1, k1, err := ChiffrerCle(clair)
	if err != nil {
		t.Fatal(err)
	}
	c2, k2, err := ChiffrerCle(clair)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("deux dépôts partagent la même clé : la clé doit être à usage unique")
	}
	if bytes.Equal(c1[1:1+TailleNonce], c2[1:1+TailleNonce]) {
		t.Fatal("deux dépôts partagent le même nonce")
	}
}

func TestSchemaInvalide(t *testing.T) {
	if _, err := Schema(nil); err == nil {
		t.Error("chiffré vide accepté")
	}
	if _, err := Schema([]byte{0x7f, 0x00}); err == nil {
		t.Error("version inconnue acceptée")
	}
	// Les versions 0x02 et 0x03 (ex-CHIF-1/3) sont rejetées
	if _, err := Schema([]byte{0x02, 0x00}); err == nil {
		t.Error("version 0x02 (ex-CHIF-3) doit être rejetée")
	}
	if _, err := Schema([]byte{0x03, 0x00}); err == nil {
		t.Error("version 0x03 (ex-CHIF-1) doit être rejetée")
	}
	if _, err := Dechiffrer([]byte{VersionCle, 1, 2, 3}, make([]byte, TailleCle)); err == nil {
		t.Error("chiffré tronqué accepté")
	}
}

// TestBesoinMots vérifie le dispatch BesoinMots pour chaque version connue
// et pour des versions inconnues (PR-010).
func TestBesoinMots(t *testing.T) {
	if !BesoinMots(VersionMots) {
		t.Error("BesoinMots(VersionMots) doit retourner true")
	}
	for _, v := range []byte{VersionCle, VersionServeur, VersionMultiDest, 0x00, 0x02, 0x03, 0xFF} {
		if BesoinMots(v) {
			t.Errorf("BesoinMots(0x%02x) doit retourner false", v)
		}
	}
}

func TestEffacer(t *testing.T) {
	cle := []byte{1, 2, 3, 4}
	motDePasse := []byte{5, 6}
	Effacer(cle, motDePasse, nil)
	for i, b := range append(cle, motDePasse...) {
		if b != 0 {
			t.Fatalf("octet %d non effacé", i)
		}
	}
}

func TestIdentifiantServeur(t *testing.T) {
	vus := map[string]bool{}
	for i := 0; i < 64; i++ {
		id, err := NouvelIDServeur()
		if err != nil {
			t.Fatal(err)
		}
		if !IDServeurValide(id) {
			t.Fatalf("identifiant généré invalide : %q", id)
		}
		if vus[id] {
			t.Fatalf("identifiant répété : %q", id)
		}
		vus[id] = true
	}
	for _, invalide := range []string{
		"", "court", "a7f3k9x2m4n", "a7f3k9x2m4n6b", "A7f3k9x2m4n6",
		"a7f3k9x2m4n0", "a7f3k9x2m4n1", "a7f3k9x2m4.6", "a7f3k9x2m4/6",
	} {
		if IDServeurValide(invalide) {
			t.Errorf("identifiant %q accepté à tort", invalide)
		}
	}
	if !IDServeurValide("abcdefghij29") {
		t.Error("identifiant valide refusé")
	}
}

func TestFormatEtParseIdentifiant(t *testing.T) {
	cle := bytes.Repeat([]byte{0xa5}, TailleCle)
	complet := FormatIdentifiant("abcdefghij29", cle)
	if !strings.HasPrefix(complet, "abcdefghij29#") {
		t.Fatalf("identifiant = %q", complet)
	}
	id, cleRendue, err := ParseIdentifiant(complet)
	if err != nil {
		t.Fatal(err)
	}
	if id != "abcdefghij29" || !bytes.Equal(cleRendue, cle) {
		t.Fatalf("id = %q, clé rendue ≠ clé d'origine", id)
	}

	// Sans fragment : l'identifiant se réduit à la partie serveur.
	if s := FormatIdentifiant("abcdefghij29", nil); s != "abcdefghij29" {
		t.Fatalf("identifiant sans fragment = %q", s)
	}
	id, cleRendue, err = ParseIdentifiant(" abcdefghij29\n")
	if err != nil || id != "abcdefghij29" || cleRendue != nil {
		t.Fatalf("id = %q, clé = %v, err = %v", id, cleRendue, err)
	}

	for _, invalide := range []string{
		"abcdefghij2#" + strings.Repeat("A", 43),
		"abcdefghij29#pas-du-base64url-!!",
		"abcdefghij29#" + strings.Repeat("A", 10),
		"abcdefghij29#",
	} {
		if _, _, err := ParseIdentifiant(invalide); err == nil {
			t.Errorf("identifiant %q accepté à tort", invalide)
		}
	}
}

func TestEmpreinte(t *testing.T) {
	if e := Empreinte([]byte("abc")); e != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("empreinte = %s", e)
	}
	e := Empreinte([]byte("contenu"))
	if !EmpreintesEgales(e, e) {
		t.Error("empreinte inégale à elle-même")
	}
	if !EmpreintesEgales(e, "sha256:"+strings.ToUpper(e)) {
		t.Error("préfixe sha256: et casse non normalisés")
	}
	if EmpreintesEgales(e, Empreinte([]byte("autre"))) {
		t.Error("empreintes distinctes déclarées égales")
	}
	if EmpreintesEgales(e, "zz") || EmpreintesEgales("", "") {
		t.Error("valeur non hexadécimale acceptée")
	}
}

// TestDecouperVide : X1 — decouper([]byte{}) ne panique pas.
func TestDecouperVide(t *testing.T) {
	_, _, _, _, err := decouper([]byte{})
	if err == nil {
		t.Error("decouper sur chiffré vide doit retourner une erreur")
	}
}

// TestVersionMotsDecouper vérifie que decouper extrait blob_salt pour 0x06.
func TestVersionMotsDecouper(t *testing.T) {
	cle := bytes.Repeat([]byte{0x42}, TailleCle)
	blobSalt := bytes.Repeat([]byte{0x99}, TailleBlobSalt)
	clair := []byte("test CHIF-5")
	chiffre, err := ChiffrerMotsAvecCle(blobSalt, cle, clair)
	if err != nil {
		t.Fatal(err)
	}
	if chiffre[0] != VersionMots {
		t.Fatalf("version = 0x%02x, attendu 0x06", chiffre[0])
	}
	enTete, sel, _, _, err := decouper(chiffre)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != TailleBlobSalt || !bytes.Equal(sel, blobSalt) {
		t.Fatalf("blob_salt = %x, attendu %x", sel, blobSalt)
	}
	// AAD = version + blobSalt
	attendu := append([]byte{VersionMots}, blobSalt...)
	if !bytes.Equal(enTete, attendu) {
		t.Fatalf("enTete = %x, attendu %x", enTete, attendu)
	}
}
