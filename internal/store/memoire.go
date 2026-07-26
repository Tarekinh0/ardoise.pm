package store

import (
	"context"
	"sync"
	"time"
)

// Memoire est le magasin en mémoire vive (RET-1, RET-2) : aucune
// persistance, contenus perdus au redémarrage — comportement assumé
// (docs/dat.md §5.3). PR-107 : les champs partagés (horloge, arret,
// fermer, rappel) sont portés par magasinBase.
type Memoire struct {
	magasinBase

	mu       sync.RWMutex
	ardoises map[string]*Ardoise
}

// notifier invoque le rappel pour chaque destruction, hors verrou.
func (m *Memoire) notifier(detruites []*Ardoise, cause string) {
	if m.rappel == nil {
		return
	}
	for _, a := range detruites {
		m.rappel(a.ID, a.Empreinte, cause)
	}
}

// NouveauMemoire crée le magasin et démarre son balayage d'expiration, qui
// s'arrête à l'annulation du contexte ou à l'appel de Fermer. La période
// règle la fréquence du balayage ; l'expiration paresseuse à la lecture
// garantit qu'aucune ardoise expirée n'est jamais servie entre deux
// passages.
func NouveauMemoire(ctx context.Context, periode time.Duration) *Memoire {
	m := &Memoire{
		ardoises: make(map[string]*Ardoise),
		magasinBase: magasinBase{
			horloge: time.Now,
			arret:   make(chan struct{}),
		},
	}
	go m.balayer(ctx, periode, m.purgerExpirees)
	return m
}

// DefinirRappelDestruction installe le rappel de destruction (PR-106).
// Satisfait NotifiantDestruction.
func (m *Memoire) DefinirRappelDestruction(rappel RappelDestruction) {
	m.magasinBase.definirRappelDestruction(rappel)
}

// Deposer conserve une copie du contenu : l'appelant reste libre de
// réutiliser ses tampons.
//
// S1 : lorsque maxArdoises est atteint, ErrSature est retourné.
func (m *Memoire) Deposer(a *Ardoise) error {
	copie := *a
	copie.Chiffre = append([]byte(nil), a.Chiffre...)
	if a.Pour != nil {
		copie.Pour = append([]string(nil), a.Pour...)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, existe := m.ardoises[a.ID]; existe {
		return ErrExiste
	}
	if m.maxArdoises > 0 && len(m.ardoises) >= m.maxArdoises {
		return ErrSature
	}
	m.ardoises[a.ID] = &copie
	return nil
}

// Recuperer applique l'expiration paresseuse puis, le cas échéant, la
// destruction à la première lecture : le retrait de la table sous verrou
// rend la consommation atomique, une seule lecture concurrente obtient le
// contenu.
func (m *Memoire) Recuperer(id string) (*Ardoise, error) {
	return m.RecupererSi(id, nil)
}

// RecupererSi applique l'expiration paresseuse, évalue le prédicat AVANT
// toute consommation (un lecteur refusé ne détruit rien), puis la
// destruction à la première lecture : le retrait de la table sous verrou
// rend la consommation atomique, une seule lecture concurrente obtient le
// contenu.
func (m *Memoire) RecupererSi(id string, admis func(*Ardoise) bool) (*Ardoise, error) {
	m.mu.Lock()
	a, existe := m.ardoises[id]
	if !existe {
		m.mu.Unlock()
		return nil, ErrIntrouvable
	}
	if !m.horloge().Before(a.Echeance) {
		delete(m.ardoises, id)
		m.mu.Unlock()
		m.notifier([]*Ardoise{a}, DestructionEcheance)
		return nil, ErrIntrouvable
	}
	if admis != nil && !admis(a) {
		m.mu.Unlock()
		return nil, ErrNonAdmis
	}
	if a.LectureUnique {
		delete(m.ardoises, id)
		m.mu.Unlock()
		m.notifier([]*Ardoise{a}, DestructionLecture)
		return a, nil
	}
	m.mu.Unlock()
	return a, nil
}

// Fermer arrête le balayage et vide la table. Les ardoises encore présentes
// sont notifiées comme détruites par échéance avant d'être effacées, afin
// que le journal d'imputabilité reçoive les horodatages de destruction
// (ADR-005) avant que le puits de journalisation ne soit fermé.
func (m *Memoire) Fermer() error {
	m.fermer.Do(func() {
		close(m.arret)
		m.mu.Lock()
		// Drainer les entrées restantes à travers le rappel de destruction
		// avant de vider la table, afin que les événements de destruction
		// atteignent le journal avant sa fermeture (PR-001).
		var detruites []*Ardoise
		for id, a := range m.ardoises {
			delete(m.ardoises, id)
			detruites = append(detruites, a)
		}
		m.ardoises = make(map[string]*Ardoise)
		m.mu.Unlock()
		m.notifier(detruites, DestructionEcheance)
	})
	return nil
}

func (m *Memoire) purgerExpirees() {
	maintenant := m.horloge()
	var detruites []*Ardoise
	m.mu.Lock()
	for id, a := range m.ardoises {
		if !maintenant.Before(a.Echeance) {
			delete(m.ardoises, id)
			detruites = append(detruites, a)
		}
	}
	m.mu.Unlock()
	m.notifier(detruites, DestructionEcheance)
}
