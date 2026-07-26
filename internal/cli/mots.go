// Package cli — extension CHIF-5 (mots mnémoniques)
//
// Implémente les flags --mots pour push et get, la saisie
// interactive des mots, et l'affichage formaté.

package cli

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"ardoise.pm/internal/crypto"
)

// saisirMots lit n mots sur le terminal /dev/tty. L'invite est "Mots : ".
// Accepte les mots séparés par des espaces ou des tirets.
// Retourne une erreur si moins de n mots ou mots hors liste.
// Jamais depuis argv : la saisie interactive est obligatoire (docs/man.md).
func saisirMots(n int) ([]string, error) {
	if n <= 0 {
		return nil, errors.New("nombre de mots invalide")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("aucun terminal disponible pour saisir les mots : %w", err)
	}
	defer tty.Close()

	fmt.Fprintf(os.Stderr, "Mots : ")
	lecteur := bufio.NewReader(tty)
	ligne, err := lecteur.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("lecture des mots : %w", err)
	}
	// Accepter les tirets ET les espaces comme séparateurs.
	ligne = strings.TrimSpace(strings.ReplaceAll(ligne, "-", " "))
	mots := strings.Fields(ligne)
	if len(mots) != n {
		return nil, fmt.Errorf("%d mots attendus, %d saisis", n, len(mots))
	}
	if !crypto.MotsValides(mots) {
		return nil, errors.New("un ou plusieurs mots ne font pas partie de la liste BIP39 française")
	}
	return mots, nil
}

// afficherMots écrit les mots sur la sortie standard. En mode TTY,
// groupe par ligne pour lisibilité.
func afficherMots(w io.Writer, mots []string, tty bool) {
	if tty && len(mots) > 0 {
		// Grouper par 3 puis 2 pour lisibilité
		for i, m := range mots {
			if i > 0 {
				if i == 3 {
					fmt.Fprintln(w)
				} else {
					fmt.Fprint(w, "-")
				}
			}
			fmt.Fprint(w, m)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, strings.Join(mots, "-"))
	}
}

// preparerChiffrementMots gère le chiffrement CHIF-5 côté client
// (mode aveugle) : génère les mots, dérive graine/ID/clé, chiffre.
// Retourne le chiffré complet (version 0x06 ‖ blob_salt ‖ nonce ‖ scellé),
// l'identifiant serveur dérivé (pour id_suggere), les mots pour affichage,
// et la clé pour l'appelant (qui l'effacera).
func preparerChiffrementMots(clair []byte) (chiffre, cle []byte, mots []string, idSuggere string, err error) {
	mots, err = crypto.GenererMots(5)
	if err != nil {
		return nil, nil, nil, "", err
	}
	graine := crypto.DeriverGraine(mots)
	defer crypto.Effacer(graine)

	idSuggere, err = crypto.DeriverIDDepuisGraine(graine)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("dérivation de l'identifiant serveur : %w", err)
	}

	blobSalt := make([]byte, crypto.TailleBlobSalt)
	if _, err := rand.Read(blobSalt); err != nil {
		return nil, nil, nil, "", fmt.Errorf("génération du blob_salt : %w", err)
	}
	cle, err = crypto.DeriverCleDepuisGraine(graine, blobSalt)
	if err != nil {
		return nil, nil, nil, "", err
	}
	chiffre, err = crypto.ChiffrerMotsAvecCle(blobSalt, cle, clair)
	if err != nil {
		crypto.Effacer(cle)
		return nil, nil, nil, "", err
	}
	return chiffre, cle, mots, idSuggere, nil
}

// dechiffrerMots gère le déchiffrement CHIF-5 côté client :
// mots → graine → ID → extraire blob_salt → cle → déchiffrer.
// Le chiffré est fourni par l'appelant (qui a déjà fait le GET).
// Retourne le clair.
func dechiffrerMots(chiffre []byte, mots []string) ([]byte, error) {
	graine := crypto.DeriverGraine(mots)
	defer crypto.Effacer(graine)

	// Découper le chiffré pour extraire le blob_salt (sel)
	_, sel, _, _, err := crypto.Decouper(chiffre)
	if err != nil {
		return nil, fmt.Errorf("extraction du blob_salt : %w", err)
	}
	cle, err := crypto.DeriverCleDepuisGraine(graine, sel)
	if err != nil {
		return nil, err
	}
	defer crypto.Effacer(cle)

	clair, err := crypto.Dechiffrer(chiffre, cle)
	if err != nil {
		return nil, err
	}
	return clair, nil
}
