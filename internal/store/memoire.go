package store

import (
	"context"
	"sync"
	"time"
)

// Memoire est le magasin en mémoire vive (RET-1, RET-2) : aucune
// persistance, contenus perdus au redémarrage — comportement assumé
// (docs/dat.md §5.3).
type Memoire struct {
	mu       sync.RWMutex
	ardoises map[string]*Ardoise

	horloge func() time.Time
	arret   chan struct{}
	fermer  sync.Once

	// rappel, s'il est défini (une fois, avant mise en service), est
	// invoqué hors verrou après chaque destruction effective.
	rappel RappelDestruction
}

// DefinirRappelDestruction installe le rappel de destruction
// (NotifiantDestruction). À appeler avant la mise en service du magasin.
func (m *Memoire) DefinirRappelDestruction(rappel RappelDestruction) {
	m.rappel = rappel
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
		horloge:  time.Now,
		arret:    make(chan struct{}),
	}
	go m.balayer(ctx, periode)
	return m
}

// Deposer conserve une copie du contenu : l'appelant reste libre de
// réutiliser ses tampons.
func (m *Memoire) Deposer(a *Ardoise) error {
	copie := *a
	copie.Chiffre = append([]byte(nil), a.Chiffre...)

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, existe := m.ardoises[a.ID]; existe {
		return ErrExiste
	}
	m.ardoises[a.ID] = &copie
	return nil
}

// Recuperer applique l'expiration paresseuse puis, le cas échéant, la
// destruction à la première lecture : le retrait de la table sous verrou
// rend la consommation atomique, une seule lecture concurrente obtient le
// contenu.
func (m *Memoire) Recuperer(id string) (*Ardoise, error) {
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
	if a.LectureUnique {
		delete(m.ardoises, id)
		m.mu.Unlock()
		m.notifier([]*Ardoise{a}, DestructionLecture)
		return a, nil
	}
	m.mu.Unlock()
	return a, nil
}

// Fermer arrête le balayage et vide la table.
func (m *Memoire) Fermer() error {
	m.fermer.Do(func() {
		close(m.arret)
		m.mu.Lock()
		m.ardoises = make(map[string]*Ardoise)
		m.mu.Unlock()
	})
	return nil
}

func (m *Memoire) balayer(ctx context.Context, periode time.Duration) {
	ticker := time.NewTicker(periode)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.arret:
			return
		case <-ticker.C:
			m.purgerExpirees()
		}
	}
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
