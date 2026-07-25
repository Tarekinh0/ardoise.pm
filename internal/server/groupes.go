package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Syntaxes des destinataires (docs/man.md, « --pour ») : une identité
// individuelle « alice.durand » ou un groupe « @equipe-reseau ».
var (
	reIdentiteDestinataire = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	reGroupeDestinataire   = regexp.MustCompile(`^@[a-z0-9._-]{1,64}$`)
)

// DestinataireValide indique si une entrée du champ « pour » a la forme
// d'une identité individuelle ou d'un groupe.
func DestinataireValide(d string) bool {
	return reIdentiteDestinataire.MatchString(d) || reGroupeDestinataire.MatchString(d)
}

// Groupes est la table des groupes de destinataires, chargée au démarrage
// depuis auth.groupes (optionnelle) : un fichier JSON associant chaque
// groupe à ses membres, par exemple :
//
//	{
//	  "@equipe-reseau": ["alice.durand", "bruno.marchal"]
//	}
//
// La table ne porte aucun secret — l'appartenance à un groupe n'est pas un
// matériel d'authentification, l'identité du lecteur ayant déjà été
// authentifiée par le mécanisme de l'instance. Au moment de la lecture, un
// groupe absent de la table (ou une table absente) ne correspond simplement
// à aucune identité : la désignation reste alors sans effet pour ce groupe,
// jamais un accès élargi. Un Groupes nil est valide et ne résout rien.
type Groupes struct {
	membres map[string]map[string]bool // groupe → identités membres
}

// ChargerGroupes lit et valide la table des groupes au chemin donné.
func ChargerGroupes(chemin string) (*Groupes, error) {
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("table des groupes : %w", err)
	}
	g, err := AnalyserGroupes(donnees)
	if err != nil {
		return nil, fmt.Errorf("table des groupes %s : %w", chemin, err)
	}
	return g, nil
}

// AnalyserGroupes décode strictement la table JSON groupe → membres :
// noms de groupes préfixés d'une arobase, identités à la syntaxe des
// destinataires — tout écart est une erreur de démarrage, comme pour la
// table des jetons.
func AnalyserGroupes(donnees []byte) (*Groupes, error) {
	dec := json.NewDecoder(bytes.NewReader(donnees))
	dec.DisallowUnknownFields()
	var table map[string][]string
	if err := dec.Decode(&table); err != nil {
		return nil, fmt.Errorf("illisible : %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("contenu excédentaire après l'objet racine")
	}
	g := &Groupes{membres: make(map[string]map[string]bool, len(table))}
	for groupe, identites := range table {
		if !reGroupeDestinataire.MatchString(groupe) {
			return nil, fmt.Errorf("nom de groupe « %s » invalide (attendu : « @nom », caractères a-z 0-9 . _ -)", groupe)
		}
		ensemble := make(map[string]bool, len(identites))
		for _, identite := range identites {
			if !reIdentiteDestinataire.MatchString(identite) {
				return nil, fmt.Errorf("groupe « %s » : identité invalide (attendu : caractères a-z 0-9 . _ -, 64 au plus)", groupe)
			}
			ensemble[identite] = true
		}
		g.membres[groupe] = ensemble
	}
	return g, nil
}

// Membre indique si l'identité appartient au groupe. Sur une table nil ou
// un groupe inconnu, la réponse est toujours négative : un groupe
// irrésoluble ne correspond à aucune identité (voir le commentaire de type).
func (g *Groupes) Membre(groupe, identite string) bool {
	if g == nil {
		return false
	}
	return g.membres[groupe][identite]
}

// LecteurAdmis indique si l'identité authentifiée est admise par la liste
// de destinataires d'une ardoise : liste vide — ardoise au porteur — tout
// lecteur authentifié est admis ; sinon, l'identité doit être désignée
// directement ou appartenir à l'un des groupes désignés.
func (g *Groupes) LecteurAdmis(pour []string, identite string) bool {
	if len(pour) == 0 {
		return true
	}
	if identite == "" {
		return false
	}
	for _, d := range pour {
		if len(d) > 0 && d[0] == '@' {
			if g.Membre(d, identite) {
				return true
			}
			continue
		}
		if d == identite {
			return true
		}
	}
	return false
}
