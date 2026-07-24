//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// lireMotDePasseTerminal demande un mot de passe sur /dev/tty, écho coupé.
//
// Le manuel l'exige (« Le mot de passe n'est jamais un argument. Il est
// demandé au terminal. ») ; le mot de passe ne doit ni s'afficher, ni
// transiter par l'entrée standard — celle-ci porte le contenu à déposer ou
// l'identifiant (« get - »).
//
// La coupure d'écho s'appuie sur les ioctl TCGETS/TCSETS du paquet syscall
// de la bibliothèque standard : le budget de dépendances du projet (stdlib
// + golang.org/x/crypto seul) exclut golang.org/x/term, et la cible du
// produit est Linux (AGENTS.md). La saisie est lue octet par octet et
// retournée en []byte, jamais convertie en chaîne (annexe B).
func lireMotDePasseTerminal(invite string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("aucun terminal disponible pour saisir le mot de passe")
	}
	defer tty.Close()

	fd := tty.Fd()
	var etatInitial syscall.Termios
	if err := ioctlTermios(fd, syscall.TCGETS, &etatInitial); err != nil {
		return nil, fmt.Errorf("préparation du terminal : %v", err)
	}
	etatSansEcho := etatInitial
	etatSansEcho.Lflag &^= syscall.ECHO
	if err := ioctlTermios(fd, syscall.TCSETS, &etatSansEcho); err != nil {
		return nil, fmt.Errorf("préparation du terminal : %v", err)
	}
	defer func() {
		_ = ioctlTermios(fd, syscall.TCSETS, &etatInitial)
		// L'écho étant coupé, le retour à la ligne de l'utilisateur ne
		// s'est pas affiché.
		fmt.Fprintln(tty)
	}()

	fmt.Fprint(tty, invite)
	var motDePasse []byte
	octet := make([]byte, 1)
	for {
		n, err := tty.Read(octet)
		if n > 0 {
			if octet[0] == '\n' || octet[0] == '\r' {
				break
			}
			motDePasse = append(motDePasse, octet[0])
		}
		if err != nil {
			if len(motDePasse) > 0 {
				break
			}
			return nil, errors.New("saisie du mot de passe interrompue")
		}
	}
	if len(motDePasse) == 0 {
		return nil, errors.New("mot de passe vide")
	}
	return motDePasse, nil
}

func ioctlTermios(fd uintptr, requete uint, termios *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(requete), uintptr(unsafe.Pointer(termios)))
	if errno != 0 {
		return errno
	}
	return nil
}
