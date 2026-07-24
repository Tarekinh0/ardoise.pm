package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
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

// TestVecteurFormatCHIF2 vérifie le format du chiffré par construction
// manuelle : avec clé et nonce fixés, le chiffré doit être exactement
// version ‖ nonce ‖ Seal(nonce, clair, AAD = version).
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

	// Le même chiffré s'ouvre par la voie publique du paquet.
	rendu, err := Dechiffrer(obtenu, cle, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendu, clair) {
		t.Fatalf("clair = %q", rendu)
	}
}

// TestVecteurFormatCHIF3 vérifie par construction manuelle que CHIF-3
// emploie exactement Argon2id(64 Mio, 3 itérations, parallélisme 4) avec le
// sel de l'en-tête : le test dérive lui-même la clé avec ces paramètres et
// ouvre le chiffré à la main. Des paramètres différents dans le paquet
// feraient échouer l'ouverture.
func TestVecteurFormatCHIF3(t *testing.T) {
	motDePasse := []byte("tournesol")
	clair := []byte("clair CHIF-3")
	chiffre, err := ChiffrerMotDePasse(clair, motDePasse)
	if err != nil {
		t.Fatal(err)
	}
	if chiffre[0] != VersionMotDePasse {
		t.Fatalf("version = 0x%02x", chiffre[0])
	}
	sel := chiffre[1 : 1+TailleSel]
	nonce := chiffre[1+TailleSel : 1+TailleSel+TailleNonce]
	scelle := chiffre[1+TailleSel+TailleNonce:]

	cleAEAD := argon2.IDKey(motDePasse, sel, 3, 64*1024, 4, 32)
	bloc, _ := aes.NewCipher(cleAEAD)
	gcm, _ := cipher.NewGCM(bloc)
	rendu, err := gcm.Open(nil, nonce, scelle, chiffre[:1+TailleSel])
	if err != nil {
		t.Fatalf("ouverture manuelle : %v (les paramètres Argon2id du paquet dévient de l'annexe B ?)", err)
	}
	if !bytes.Equal(rendu, clair) {
		t.Fatalf("clair = %q", rendu)
	}
}

// TestVecteurFormatCHIF1 reconstruit la dérivation CHIF-1 documentée —
// HKDF-SHA256(K ‖ Argon2id(P, sel), sel, info) — et ouvre le chiffré à la
// main, prouvant que la construction du paquet est bien celle annoncée.
func TestVecteurFormatCHIF1(t *testing.T) {
	motDePasse := []byte("cadenas")
	clair := []byte("clair CHIF-1")
	chiffre, cle, err := ChiffrerCleMotDePasse(clair, motDePasse)
	if err != nil {
		t.Fatal(err)
	}
	if chiffre[0] != VersionCleMotDePasse {
		t.Fatalf("version = 0x%02x", chiffre[0])
	}
	sel := chiffre[1 : 1+TailleSel]
	nonce := chiffre[1+TailleSel : 1+TailleSel+TailleNonce]
	scelle := chiffre[1+TailleSel+TailleNonce:]

	derivee := argon2.IDKey(motDePasse, sel, 3, 64*1024, 4, 32)
	secret := append(append([]byte(nil), cle...), derivee...)
	cleAEAD, err := hkdf.Key(sha256.New, secret, sel, "ardoise.pm CHIF-1 v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	bloc, _ := aes.NewCipher(cleAEAD)
	gcm, _ := cipher.NewGCM(bloc)
	rendu, err := gcm.Open(nil, nonce, scelle, chiffre[:1+TailleSel])
	if err != nil {
		t.Fatalf("ouverture manuelle : %v (la dérivation CHIF-1 dévie de la construction documentée ?)", err)
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
	motDePasse := []byte("horizon")

	t.Run("CHIF-2", func(t *testing.T) {
		chiffre, cle, err := ChiffrerCle(clair)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := Schema(chiffre); v != VersionCle || !BesoinCle(v) || BesoinMotDePasse(v) {
			t.Fatalf("schéma inattendu 0x%02x", v)
		}
		rendu, err := Dechiffrer(chiffre, cle, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q", rendu)
		}
	})

	t.Run("CHIF-3", func(t *testing.T) {
		chiffre, err := ChiffrerMotDePasse(clair, motDePasse)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := Schema(chiffre); v != VersionMotDePasse || BesoinCle(v) || !BesoinMotDePasse(v) {
			t.Fatalf("schéma inattendu 0x%02x", v)
		}
		rendu, err := Dechiffrer(chiffre, nil, motDePasse)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q", rendu)
		}
	})

	t.Run("CHIF-1", func(t *testing.T) {
		chiffre, cle, err := ChiffrerCleMotDePasse(clair, motDePasse)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := Schema(chiffre); v != VersionCleMotDePasse || !BesoinCle(v) || !BesoinMotDePasse(v) {
			t.Fatalf("schéma inattendu 0x%02x", v)
		}
		rendu, err := Dechiffrer(chiffre, cle, motDePasse)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rendu, clair) {
			t.Fatalf("clair = %q", rendu)
		}
	})
}

// TestAlterationDetectee retourne chaque octet du chiffré un à un : toute
// altération — en-tête, sel, nonce ou corps — doit faire échouer
// l'ouverture avec l'erreur unique ErrDechiffrement.
func TestAlterationDetectee(t *testing.T) {
	clair := []byte("intégrité")
	chiffre, cle, err := ChiffrerCle(clair)
	if err != nil {
		t.Fatal(err)
	}
	for i := range chiffre {
		altere := append([]byte(nil), chiffre...)
		altere[i] ^= 0x01
		if _, err := Dechiffrer(altere, cle, nil); err == nil {
			t.Fatalf("altération de l'octet %d non détectée", i)
		}
	}
	if _, err := Dechiffrer(chiffre[:len(chiffre)-1], cle, nil); err == nil {
		t.Fatal("troncature non détectée")
	}
}

func TestMauvaisMaterielRefuse(t *testing.T) {
	clair := []byte("secret")
	motDePasse := []byte("bon-mot-de-passe")

	t.Run("mauvaise clé CHIF-2", func(t *testing.T) {
		chiffre, cle, err := ChiffrerCle(clair)
		if err != nil {
			t.Fatal(err)
		}
		mauvaise := append([]byte(nil), cle...)
		mauvaise[0] ^= 0xff
		if _, err := Dechiffrer(chiffre, mauvaise, nil); err != ErrDechiffrement {
			t.Fatalf("erreur = %v, attendu ErrDechiffrement", err)
		}
	})

	t.Run("mauvais mot de passe CHIF-3", func(t *testing.T) {
		chiffre, err := ChiffrerMotDePasse(clair, motDePasse)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Dechiffrer(chiffre, nil, []byte("mauvais")); err != ErrDechiffrement {
			t.Fatalf("erreur = %v, attendu ErrDechiffrement", err)
		}
	})
}

// TestCHIF1ExigeLesDeuxSecrets vérifie la propriété centrale de CHIF-1 :
// aucun des deux secrets ne suffit seul.
func TestCHIF1ExigeLesDeuxSecrets(t *testing.T) {
	clair := []byte("deux secrets requis")
	motDePasse := []byte("second-secret")
	chiffre, cle, err := ChiffrerCleMotDePasse(clair, motDePasse)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Dechiffrer(chiffre, cle, nil); err == nil {
		t.Fatal("ouverture avec la seule clé : le mot de passe doit être nécessaire")
	}
	if _, err := Dechiffrer(chiffre, nil, motDePasse); err == nil {
		t.Fatal("ouverture avec le seul mot de passe : la clé doit être nécessaire")
	}
	mauvaiseCle := append([]byte(nil), cle...)
	mauvaiseCle[TailleCle-1] ^= 0x01
	if _, err := Dechiffrer(chiffre, mauvaiseCle, motDePasse); err != ErrDechiffrement {
		t.Fatalf("clé altérée : erreur = %v, attendu ErrDechiffrement", err)
	}
	if _, err := Dechiffrer(chiffre, cle, []byte("mauvais")); err != ErrDechiffrement {
		t.Fatalf("mauvais mot de passe : erreur = %v, attendu ErrDechiffrement", err)
	}
	if _, err := Dechiffrer(chiffre, cle, motDePasse); err != nil {
		t.Fatalf("les deux bons secrets doivent ouvrir : %v", err)
	}
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

func TestChiffrementSansMotDePasseRefuse(t *testing.T) {
	if _, err := ChiffrerMotDePasse([]byte("x"), nil); err == nil {
		t.Error("CHIF-3 sans mot de passe doit être refusé")
	}
	if _, _, err := ChiffrerCleMotDePasse([]byte("x"), nil); err == nil {
		t.Error("CHIF-1 sans mot de passe doit être refusé")
	}
}

func TestSchemaInvalide(t *testing.T) {
	if _, err := Schema(nil); err == nil {
		t.Error("chiffré vide accepté")
	}
	if _, err := Schema([]byte{0x7f, 0x00}); err == nil {
		t.Error("version inconnue acceptée")
	}
	if _, err := Dechiffrer([]byte{VersionCle, 1, 2, 3}, make([]byte, TailleCle), nil); err == nil {
		t.Error("chiffré tronqué accepté")
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

	// Sans fragment (CHIF-3) : l'identifiant se réduit à la partie serveur.
	if s := FormatIdentifiant("abcdefghij29", nil); s != "abcdefghij29" {
		t.Fatalf("identifiant sans fragment = %q", s)
	}
	id, cleRendue, err = ParseIdentifiant(" abcdefghij29\n")
	if err != nil || id != "abcdefghij29" || cleRendue != nil {
		t.Fatalf("id = %q, clé = %v, err = %v", id, cleRendue, err)
	}

	for _, invalide := range []string{
		"abcdefghij2#" + strings.Repeat("A", 43),  // partie serveur trop courte
		"abcdefghij29#pas-du-base64url-!!",        // fragment illisible
		"abcdefghij29#" + strings.Repeat("A", 10), // fragment trop court
		"abcdefghij29#", // fragment vide
	} {
		if _, _, err := ParseIdentifiant(invalide); err == nil {
			t.Errorf("identifiant %q accepté à tort", invalide)
		}
	}
}

func TestEmpreinte(t *testing.T) {
	// Vecteur SHA-256 connu : sha256("abc").
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
