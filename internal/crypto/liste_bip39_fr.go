// Package crypto — liste BIP39 française embarquée.
//
// La liste contient 2048 mots uniques, triés, en minuscules. Elle
// sert la génération de mots mnémoniques du schéma CHIF-5
// (docs/dat.md, annexe B). L'intégrité de la liste est vérifiée
// au chargement (TestIntegriteListeBIP39).
package crypto

import (
	_ "embed"
	"strings"
)

//go:embed bip39_french.txt
var listeBIP39Brute string

// ListeBIP39 est la liste BIP39 française, chargée au chargement du paquet.
// La variable est remplie par init() pour que les tests de liste ne
// dépendent pas de l'ordre d'initialisation.
var ListeBIP39 []string

// init() charge la liste BIP39 embarquée à l'initialisation du paquet.
// L'usage d'init() est ici nécessaire car :
//   - La liste est chargée via //go:embed, ce qui exige une variable
//     de niveau paquet (listeBIP39Brute).
//   - Les fonctions GenererMots, MotsValides et le test d'intégrité
//     (TestIntegriteListeBIP39) sont appelées depuis le même paquet
//     et supposent ListeBIP39 déjà peuplée.
//   - Un chargement explicite (depuis main()) créerait une dépendance
//     circulaire entre le paquet main et internal/crypto, et exposerait
//     un état mutable de niveau paquet sans synchronisation naturelle.
//
// Effective Go déconseille init() sauf nécessité ; celle-ci est documentée
// et circonscrite.
func init() {
	// strings.Fields découpe proprement par ligne et ignore les blancs.
	ListeBIP39 = strings.Fields(listeBIP39Brute)
}
