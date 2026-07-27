package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallerPageMan(t *testing.T) {
	home := t.TempDir()

	// Première exécution : doit créer la page man.
	installerPageMan(home)

	cible := filepath.Join(home, ".local", "share", "man", "man1", "ardoise.1")
	contenu, err := os.ReadFile(cible)
	if err != nil {
		t.Fatalf("page man non créée dans %s : %v", cible, err)
	}
	if string(contenu) != pageManuel {
		t.Errorf("contenu de la page man ne correspond pas à pageManuel")
	}

	// Deuxième exécution : idempotente, ne doit pas réécrire.
	infos1, err := os.Stat(cible)
	if err != nil {
		t.Fatalf("stat page man : %v", err)
	}
	installerPageMan(home)
	infos2, err := os.Stat(cible)
	if err != nil {
		t.Fatalf("page man disparue après seconde exécution : %v", err)
	}
	if !infos1.ModTime().Equal(infos2.ModTime()) {
		t.Error("la page man a été réécrite — l'opération n'est pas idempotente")
	}
}

func TestInstallerPageManRepertoireInexistant(t *testing.T) {
	// Si le répertoire cible n'existe pas, il est créé automatiquement.
	home := t.TempDir()
	installerPageMan(home)
	cible := filepath.Join(home, ".local", "share", "man", "man1", "ardoise.1")
	if _, err := os.Stat(cible); err != nil {
		t.Fatalf("page man non créée malgré répertoire inexistant : %v", err)
	}
}

func TestInstallerBinaireUser(t *testing.T) {
	home := t.TempDir()

	// Binaire factice pour le test.
	fauxBinaire := filepath.Join(home, "ardoise-fake")
	if err := os.WriteFile(fauxBinaire, []byte("#!/bin/sh\necho fake\n"), 0755); err != nil {
		t.Fatal(err)
	}

	installerBinaire(fauxBinaire, home)

	cible := filepath.Join(home, ".local", "bin", "ardoise")
	infos1, err := os.Stat(cible)
	if err != nil {
		t.Fatalf("binaire non installé dans %s : %v", cible, err)
	}

	// Vérification du contenu.
	contenu, err := os.ReadFile(cible)
	if err != nil {
		t.Fatal(err)
	}
	if len(contenu) == 0 {
		t.Error("binaire copié vide")
	}

	// Idempotence : la deuxième exécution ne modifie pas le fichier.
	installerBinaire(fauxBinaire, home)
	infos2, err := os.Stat(cible)
	if err != nil {
		t.Fatal(err)
	}
	if !infos1.ModTime().Equal(infos2.ModTime()) {
		t.Error("le binaire a été réinstallé — l'opération n'est pas idempotente")
	}
}

func TestAssurerRepertoireAccessibleFichierExistant(t *testing.T) {
	tmp := t.TempDir()
	fichier := filepath.Join(tmp, "existant")
	if err := os.WriteFile(fichier, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if assurerRepertoireAccessible(fichier) {
		t.Error("assurerRepertoireAccessible doit retourner false quand la cible existe déjà")
	}
}

func TestAssurerRepertoireAccessibleRepertoireAccessible(t *testing.T) {
	tmp := t.TempDir()
	cible := filepath.Join(tmp, "ardoise")
	if !assurerRepertoireAccessible(cible) {
		t.Error("assurerRepertoireAccessible doit retourner true pour un répertoire temporaire accessible")
	}
}

func TestAssurerRepertoireAccessibleRepertoireCree(t *testing.T) {
	// Le répertoire parent n'existe pas encore : MkdirAll est tenté.
	tmp := t.TempDir()
	cible := filepath.Join(tmp, "sousrep", "ardoise")
	if !assurerRepertoireAccessible(cible) {
		t.Error("assurerRepertoireAccessible doit créer le répertoire parent et retourner true")
	}
	if _, err := os.Stat(filepath.Dir(cible)); err != nil {
		t.Errorf("le répertoire parent n'a pas été créé : %v", err)
	}
}

func TestFaireLienOuCopie(t *testing.T) {
	tmp := t.TempDir()

	src := filepath.Join(tmp, "src")
	if err := os.WriteFile(src, []byte("contenu-test"), 0644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "dst")
	faireLienOuCopie(src, dst)

	contenu, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("dst non créé : %v", err)
	}
	if string(contenu) != "contenu-test" {
		t.Errorf("contenu = %q, attendu %q", contenu, "contenu-test")
	}

	// Idempotence : le fichier existe déjà, on ne fait rien.
	infos1, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	faireLienOuCopie(src, dst)
	infos2, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !infos1.ModTime().Equal(infos2.ModTime()) {
		t.Error("faireLienOuCopie n'est pas idempotent")
	}
}

func TestFaireLienOuCopiePreferenceLienDur(t *testing.T) {
	// Sur un même système de fichiers, os.Link() réussit : on vérifie
	// que c'est bien un lien dur (même inode) qui est privilégié.
	tmp := t.TempDir()

	src := filepath.Join(tmp, "src")
	if err := os.WriteFile(src, []byte("contenu"), 0644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "dst")
	faireLienOuCopie(src, dst)

	infosSrc, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	infosDst, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}

	// Vérification que c'est le même inode (lien dur), pas une copie.
	same := os.SameFile(infosSrc, infosDst)
	if !same {
		t.Log("lien dur non appliqué (systèmes de fichiers différents ?), " +
			"vérification par contenu à la place")
		contenuSrc, _ := os.ReadFile(src)
		contenuDst, _ := os.ReadFile(dst)
		if string(contenuSrc) != string(contenuDst) {
			t.Error("le contenu ne correspond pas")
		}
	}
}

func TestFaireLienOuCopieSourceInexistante(t *testing.T) {
	// Si la source n'existe pas, la fonction ne panique pas et retourne
	// silencieusement (PR-204 : erreurs path).
	tmp := t.TempDir()
	src := filepath.Join(tmp, "inexistant")
	dst := filepath.Join(tmp, "dst")

	// Ne doit pas paniquer.
	faireLienOuCopie(src, dst)

	// La destination ne doit pas être créée.
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("la destination ne doit pas exister quand la source est absente")
	}
}

func TestFaireLienOuCopieDestinationExistante(t *testing.T) {
	// Si la destination existe déjà (créée entre-temps, TOCTOU), on ne
	// l'écrase pas : la fonction retourne sans modifier le fichier.
	tmp := t.TempDir()

	src := filepath.Join(tmp, "src")
	if err := os.WriteFile(src, []byte("nouveau-contenu"), 0644); err != nil {
		t.Fatal(err)
	}

	// Créer dst AVANT avec un contenu différent.
	dst := filepath.Join(tmp, "dst")
	contenuOriginal := []byte("contenu-original-ne-pas-ecraser")
	if err := os.WriteFile(dst, contenuOriginal, 0644); err != nil {
		t.Fatal(err)
	}

	faireLienOuCopie(src, dst)

	// Vérifier que dst n'a PAS été écrasé.
	contenu, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(contenu) != string(contenuOriginal) {
		t.Errorf("dst a été écrasé : contenu = %q, attendu %q", contenu, contenuOriginal)
	}
}

func TestFaireLienOuCopieRepertoireDestInaccessible(t *testing.T) {
	// Si le répertoire de destination n'existe pas, CreateTemp échoue :
	// la fonction ne panique pas et retourne proprement.
	tmp := t.TempDir()

	src := filepath.Join(tmp, "src")
	if err := os.WriteFile(src, []byte("contenu"), 0644); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(tmp, "inexistant", "dst")

	// Ne doit pas paniquer.
	faireLienOuCopie(src, dst)

	// Aucune création partielle.
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("la destination ne doit pas exister")
	}
}
