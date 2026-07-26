package cli

import (
	"io"
	"os"
	"path/filepath"
)

// autoInstaller vérifie que la page de manuel et le binaire sont accessibles
// depuis les emplacements standards, et les y place si nécessaire et possible.
// L'opération est idempotente — si le fichier existe déjà, on ne fait rien.
// Aucune sortie en cas de succès ; les échecs silencieux (permissions) ne
// bloquent pas l'exécution.
func autoInstaller() {
	binaire, err := os.Executable()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	installerPageMan(home)
	installerBinaire(binaire, home)
}

// installerPageMan écrit la page ARDOISE(1) dans ~/.local/share/man/man1/
// si elle n'y est pas déjà.
func installerPageMan(home string) {
	cible := filepath.Join(home, ".local", "share", "man", "man1", "ardoise.1")
	if _, err := os.Stat(cible); err == nil {
		return // déjà installée
	}
	if err := os.MkdirAll(filepath.Dir(cible), 0755); err != nil {
		return
	}
	if err := os.WriteFile(cible, []byte(pageManuel), 0644); err != nil {
		return
	}
}

// installerBinaire copie l'exécutable courant vers /usr/local/sbin/ardoise
// si le répertoire est accessible en écriture, sinon vers ~/.local/bin/.
func installerBinaire(binaire, home string) {
	// Cible 1 : /usr/local/sbin (nécessite écriture, typiquement root)
	cibleSysteme := "/usr/local/sbin/ardoise"
	if peutEcrire(cibleSysteme) {
		faireLienOuCopie(binaire, cibleSysteme)
		return
	}
	// Cible 2 : ~/.local/bin (utilisateur, sans privilège)
	cibleUser := filepath.Join(home, ".local", "bin", "ardoise")
	if peutEcrire(cibleUser) {
		faireLienOuCopie(binaire, cibleUser)
	}
}

// peutEcrire vérifie si le répertoire parent du chemin cible existe et est
// accessible en écriture. Si la cible elle-même existe déjà, on ne fait rien.
func peutEcrire(cible string) bool {
	if _, err := os.Stat(cible); err == nil {
		return false // déjà présent
	}
	rep := filepath.Dir(cible)
	infos, err := os.Stat(rep)
	if err != nil {
		// Répertoire inexistant — tenter de le créer
		if err := os.MkdirAll(rep, 0755); err != nil {
			return false
		}
		return true
	}
	if !infos.IsDir() {
		return false
	}
	// Test d'écriture : créer un fichier temporaire dans le répertoire
	tmp, err := os.CreateTemp(rep, ".ardoise-install-")
	if err != nil {
		return false
	}
	tmp.Close()
	os.Remove(tmp.Name())
	return true
}

// faireLienOuCopie tente un lien dur (même inode, pas de duplication),
// puis un lien symbolique, puis une copie en dernier recours.
// La copie est atomique (fichier temporaire + rename via lien dur) et
// n'écrase jamais un fichier déjà présent (sémantique O_EXCL).
func faireLienOuCopie(src, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	// 1. Lien dur (préféré : même inode, suppression propre)
	if err := os.Link(src, dst); err == nil {
		return
	}
	// 2. Lien symbolique
	if err := os.Symlink(src, dst); err == nil {
		return
	}
	// 3. Copie atomique : fichier temporaire dans le même répertoire,
	//    puis lien dur vers dst (échoue si dst créé entre-temps).
	s, err := os.Open(src)
	if err != nil {
		return
	}
	defer s.Close()

	rep := filepath.Dir(dst)
	tmp, err := os.CreateTemp(rep, ".ardoise-copy-")
	if err != nil {
		return
	}
	nomTmp := tmp.Name()
	ok := false
	defer func() {
		tmp.Close()
		if !ok {
			os.Remove(nomTmp)
		}
	}()

	if _, err := io.Copy(tmp, s); err != nil {
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	if err := os.Chmod(nomTmp, 0755); err != nil {
		return
	}
	// os.Link échoue si dst existe déjà → pas d'écrasement (O_EXCL).
	if err := os.Link(nomTmp, dst); err != nil {
		return
	}
	// Supprime le nom temporaire ; l'inode survit via dst.
	os.Remove(nomTmp)
	ok = true
}
