// Package icaptest fournit des doubles de test pour l'interface icap.Analyseur.
// Ces types sont exclusivement destinés aux tests — ils ne sont jamais
// utilisés dans les chemins de production (PR-105).
package icaptest

import (
	"sync"

	"ardoise.pm/internal/icap"
)

// AnalyseurFixe est un Analyseur de test qui rend toujours le même verdict,
// sans réseau. Les tests du serveur HTTP s'en servent pour éprouver le
// pipeline du mode analysé sans maquette ICAP.
type AnalyseurFixe struct {
	Reponse icap.Verdict

	mu      sync.Mutex
	vus     int
	dernier []byte
}

// Analyser retourne le verdict fixé et retient une copie du contenu soumis
// (tests uniquement — jamais dans le produit).
func (a *AnalyseurFixe) Analyser(contenu []byte) icap.Verdict {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.vus++
	a.dernier = append([]byte(nil), contenu...)
	return a.Reponse
}

// Vus compte les soumissions reçues.
func (a *AnalyseurFixe) Vus() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vus
}

// Dernier restitue le dernier contenu soumis.
func (a *AnalyseurFixe) Dernier() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]byte(nil), a.dernier...)
}
