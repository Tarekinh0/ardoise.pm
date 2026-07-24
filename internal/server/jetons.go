package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// Jetons est la table d'authentification AUTH-3, chargée au démarrage depuis
// auth.jetons : un fichier JSON associant chaque identité à l'empreinte
// SHA-256 hexadécimale de son jeton, par exemple :
//
//	{
//	  "alice.durand": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
//	  "bruno.marchal": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
//	}
//
// Le fichier ne contient jamais les jetons eux-mêmes : seule l'empreinte est
// conservée côté instance, et la comparaison porte sur les empreintes, en
// temps constant. La source de ces identités relève du service d'identité de
// l'entité — en mode analysé, elle doit être distincte du SI
// d'administration (R56, docs/dat.md §6.3) : exigence organisationnelle,
// invérifiable ici (point d'ancrage d'exploitation).
type Jetons struct {
	entrees []entreeJeton
}

type entreeJeton struct {
	identite  string
	empreinte []byte // SHA-256 du jeton, 32 octets
}

// ChargerJetons lit et valide la table des jetons. Le fichier doit
// appartenir au seul exploitant de l'instance : des droits plus larges que
// 0600 sont un refus de démarrage, pas un avertissement.
func ChargerJetons(chemin string) (*Jetons, error) {
	infos, err := os.Stat(chemin)
	if err != nil {
		return nil, fmt.Errorf("table des jetons : %w", err)
	}
	if mode := infos.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("table des jetons %s : droits %04o trop larges (0600 au plus exigé)", chemin, mode)
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("table des jetons : %w", err)
	}
	return AnalyserJetons(donnees)
}

// AnalyserJetons décode strictement la table JSON identité → SHA-256
// hexadécimale du jeton.
func AnalyserJetons(donnees []byte) (*Jetons, error) {
	dec := json.NewDecoder(bytes.NewReader(donnees))
	dec.DisallowUnknownFields()
	var table map[string]string
	if err := dec.Decode(&table); err != nil {
		return nil, fmt.Errorf("table des jetons illisible : %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("table des jetons : contenu excédentaire après l'objet racine")
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("table des jetons vide : aucune identité ne pourrait s'authentifier")
	}
	j := &Jetons{}
	for identite, empreinteHex := range table {
		if identite == "" {
			return nil, fmt.Errorf("table des jetons : identité vide")
		}
		empreinte, err := hex.DecodeString(empreinteHex)
		if err != nil || len(empreinte) != sha256.Size {
			return nil, fmt.Errorf("table des jetons : empreinte invalide pour « %s » (attendu : SHA-256 en 64 caractères hexadécimaux)", identite)
		}
		j.entrees = append(j.entrees, entreeJeton{identite: identite, empreinte: empreinte})
	}
	return j, nil
}

// Identite retourne l'identité associée au jeton présenté. Le jeton est
// d'abord réduit à son empreinte SHA-256, puis chaque entrée est confrontée
// en temps constant (crypto/subtle), sans sortie anticipée : la durée de la
// recherche ne dépend pas de l'entrée qui correspond.
func (j *Jetons) Identite(jeton []byte) (string, bool) {
	empreinte := sha256.Sum256(jeton)
	identite, trouve := "", false
	for _, e := range j.entrees {
		if subtle.ConstantTimeCompare(empreinte[:], e.empreinte) == 1 {
			identite, trouve = e.identite, true
		}
	}
	return identite, trouve
}
