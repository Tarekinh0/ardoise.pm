package client

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cacheDeTest(t *testing.T) *Cache {
	t.Helper()
	return NouveauCache(filepath.Join(t.TempDir(), "cache"))
}

func reponseDeTest(echeance string) *ReponseArdoise {
	return &ReponseArdoise{
		Chiffre:   []byte{0x01, 0xAA, 0xBB, 0xCC},
		Empreinte: "0000000000000000000000000000000000000000000000000000000000000000",
		Echeance:  echeance,
		Marquage:  Marquage{Actif: true, Libelle: "DIFFUSION RESTREINTE", Complement: "URGENT"},
	}
}

func TestCacheEcritureLecture(t *testing.T) {
	c := cacheDeTest(t)
	echeance := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := c.Ecrire("abcdefgh2345", CacheBorne, reponseDeTest(echeance)); err != nil {
		t.Fatal(err)
	}
	entree, err := c.Lire("abcdefgh2345")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(entree.Chiffre, []byte{0x01, 0xAA, 0xBB, 0xCC}) {
		t.Error("chiffré restitué inattendu")
	}
	if entree.Politique != CacheBorne || entree.Echeance != echeance {
		t.Errorf("métadonnées : %+v", entree)
	}
	if entree.Marquage.Libelle != "DIFFUSION RESTREINTE" || entree.Marquage.Complement != "URGENT" {
		t.Errorf("marquage : %+v", entree.Marquage)
	}
	// Une autre entrée est un échec indistinct.
	if _, err := c.Lire("zzzzzzzz9999"); !errors.Is(err, ErrCacheAbsent) {
		t.Errorf("entrée absente : %v", err)
	}
}

func TestCacheRefuseInterdit(t *testing.T) {
	c := cacheDeTest(t)
	echeance := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := c.Ecrire("abcdefgh2345", CacheInterdit, reponseDeTest(echeance)); err == nil {
		t.Fatal("politique « interdit » : l'écriture doit être refusée")
	}
	if err := c.Ecrire("abcdefgh2345", "fantaisie", reponseDeTest(echeance)); err == nil {
		t.Fatal("politique inconnue : l'écriture doit être refusée")
	}
}

func TestCacheBorneExpire(t *testing.T) {
	c := cacheDeTest(t)
	if err := c.Ecrire("abcdefgh2345", CacheBorne, reponseDeTest(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Lire("abcdefgh2345"); err != nil {
		t.Fatalf("avant échéance : %v", err)
	}
	// Après l'échéance : la lecture échoue ET l'entrée est détruite.
	c.horloge = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := c.Lire("abcdefgh2345"); !errors.Is(err, ErrCacheAbsent) {
		t.Fatalf("après échéance : %v", err)
	}
	restants, _ := os.ReadDir(c.repertoire)
	if len(restants) != 0 {
		t.Errorf("l'entrée expirée doit être détruite, restent : %v", restants)
	}
}

func TestCacheLibreSansEcheance(t *testing.T) {
	c := cacheDeTest(t)
	// Sous « libre », l'échéance de l'ardoise n'est pas consignée : l'entrée
	// survit à l'échéance et n'est purgée que sur demande (CACHE-3).
	if err := c.Ecrire("abcdefgh2345", CacheLibre, reponseDeTest(time.Now().Add(time.Millisecond).UTC().Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	c.horloge = func() time.Time { return time.Now().Add(48 * time.Hour) }
	entree, err := c.Lire("abcdefgh2345")
	if err != nil {
		t.Fatalf("entrée « libre » : %v", err)
	}
	if entree.Echeance != "" {
		t.Errorf("échéance consignée sous « libre » : %q", entree.Echeance)
	}
	supprimees, conservees, err := c.PurgerExpirees()
	if err != nil || supprimees != 0 || conservees != 1 {
		t.Errorf("purge par défaut : %d supprimées, %d conservées (%v)", supprimees, conservees, err)
	}
	supprimees, err = c.PurgerTout()
	if err != nil || supprimees != 1 {
		t.Errorf("purge --tout : %d supprimées (%v)", supprimees, err)
	}
	if _, err := c.Lire("abcdefgh2345"); !errors.Is(err, ErrCacheAbsent) {
		t.Error("l'entrée doit avoir disparu après PurgerTout")
	}
}

func TestCachePurgeOpportuniste(t *testing.T) {
	c := cacheDeTest(t)
	expiree := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	valide := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := c.Ecrire("aaaaaaaa2222", CacheBorne, reponseDeTest(valide)); err != nil {
		t.Fatal(err)
	}
	// L'entrée expirée est écrite en trichant sur l'horloge du cache.
	c.horloge = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	if err := c.Ecrire("bbbbbbbb3333", CacheBorne, reponseDeTest(expiree)); err != nil {
		t.Fatal(err)
	}
	c.horloge = time.Now
	// Tout accès purge l'expirée : ici, la lecture d'une autre entrée.
	if _, err := c.Lire("aaaaaaaa2222"); err != nil {
		t.Fatal(err)
	}
	restants, _ := os.ReadDir(c.repertoire)
	if len(restants) != 2 { // .chiffre + .meta de la seule entrée valide
		t.Errorf("purge opportuniste : restent %d fichiers", len(restants))
	}
}

func TestCachePurgeExpirees(t *testing.T) {
	c := cacheDeTest(t)
	if err := c.Ecrire("bbbbbbbb3333", CacheBorne, reponseDeTest(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	if err := c.Ecrire("cccccccc4444", CacheLibre, reponseDeTest("")); err != nil {
		t.Fatal(err)
	}
	// L'entrée expirée est écrite en dernier, horloge reculée, pour
	// qu'aucune purge opportuniste ne l'emporte avant la purge explicite.
	c.horloge = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	if err := c.Ecrire("aaaaaaaa2222", CacheBorne, reponseDeTest(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	c.horloge = time.Now
	supprimees, conservees, err := c.PurgerExpirees()
	if err != nil || supprimees != 1 || conservees != 2 {
		t.Errorf("purge : %d supprimées, %d conservées (%v)", supprimees, conservees, err)
	}
}

func TestCachePurgeRepertoireAbsent(t *testing.T) {
	c := NouveauCache(filepath.Join(t.TempDir(), "jamais-cree"))
	if s, k, err := c.PurgerExpirees(); err != nil || s != 0 || k != 0 {
		t.Errorf("PurgerExpirees sur cache absent : %d/%d, %v", s, k, err)
	}
	if s, err := c.PurgerTout(); err != nil || s != 0 {
		t.Errorf("PurgerTout sur cache absent : %d, %v", s, err)
	}
	if _, err := c.Lire("abcdefgh2345"); !errors.Is(err, ErrCacheAbsent) {
		t.Errorf("Lire sur cache absent : %v", err)
	}
}

func TestCacheDroitsFichiers(t *testing.T) {
	c := cacheDeTest(t)
	if err := c.Ecrire("abcdefgh2345", CacheBorne, reponseDeTest(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))); err != nil {
		t.Fatal(err)
	}
	infos, err := os.Stat(c.repertoire)
	if err != nil {
		t.Fatal(err)
	}
	if mode := infos.Mode().Perm(); mode != 0o700 {
		t.Errorf("répertoire du cache : droits %04o, attendu 0700", mode)
	}
	entrees, err := os.ReadDir(c.repertoire)
	if err != nil || len(entrees) != 2 {
		t.Fatalf("entrées : %v (%v)", entrees, err)
	}
	for _, entree := range entrees {
		infos, err := entree.Info()
		if err != nil {
			t.Fatal(err)
		}
		if mode := infos.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s : droits %04o, attendu 0600", entree.Name(), mode)
		}
	}
}

// TestCacheSansMatiereSensible vérifie l'invariant ADR-013 : ni identifiant
// serveur, ni matériel de clé, ni clair dans les octets du cache — le nom
// des fichiers est l'empreinte de l'identifiant, le contenu est le chiffré
// tel que reçu.
func TestCacheSansMatiereSensible(t *testing.T) {
	c := cacheDeTest(t)
	id := "abcdefgh2345"
	cleFragment := "Zt8mQ4vP1nK0aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1u" // jamais confié au cache
	clair := "contenu en clair jamais écrit"
	reponse := reponseDeTest(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	if err := c.Ecrire(id, CacheBorne, reponse); err != nil {
		t.Fatal(err)
	}
	entrees, err := os.ReadDir(c.repertoire)
	if err != nil {
		t.Fatal(err)
	}
	for _, entree := range entrees {
		if strings.Contains(entree.Name(), id) {
			t.Errorf("le nom de fichier %s contient l'identifiant serveur", entree.Name())
		}
		donnees, err := os.ReadFile(filepath.Join(c.repertoire, entree.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for nom, interdit := range map[string]string{
			"identifiant serveur": id,
			"fragment de clé":     cleFragment,
			"clair":               clair,
		} {
			if bytes.Contains(donnees, []byte(interdit)) {
				t.Errorf("%s : le fichier %s contient le %s", entree.Name(), entree.Name(), nom)
			}
		}
	}
}
