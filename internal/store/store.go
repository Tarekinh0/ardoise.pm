// Package store porte le magasin éphémère d'ardoises du serveur : mémoire
// vive (RET-1, RET-2) ou disque chiffré (RET-3), balayage d'expiration en
// arrière-plan, destruction à la première lecture.
//
// Aucune base de données (docs/dat.md §4.2) : le magasin conserve des
// objets {identifiant, contenu chiffré, échéance, options} et rien d'autre.
// L'expiration est garantie par le serveur indépendamment de toute action
// client (ADR-003) : chaque lecture vérifie l'échéance (expiration
// paresseuse), et un balayage périodique détruit ce que personne ne relit.
//
// Une ardoise absente, expirée ou déjà consommée est indistinguable :
// l'unique erreur ErrIntrouvable porte les trois cas (docs/man.md, code 5).
package store

import (
	"errors"
	"time"
)

// ErrIntrouvable est l'unique erreur de récupération : elle confond
// volontairement l'inexistence, l'expiration et la consommation, afin de
// priver un tiers d'un moyen d'inférence (docs/man.md, code 5).
var ErrIntrouvable = errors.New("ardoise inexistante, expirée ou déjà consommée")

// ErrExiste signale une collision d'identifiant au dépôt ; l'appelant
// retire un nouvel identifiant et réessaie.
var ErrExiste = errors.New("identifiant déjà employé")

// Ardoise est l'objet conservé par le magasin. Le contenu est toujours du
// chiffré : en mode aveugle le serveur ne reçoit jamais autre chose.
type Ardoise struct {
	ID                 string
	Chiffre            []byte
	Empreinte          string // SHA-256 hexadécimale du chiffré
	Echeance           time.Time
	LectureUnique      bool
	MarquageComplement string // mention libre de l'émetteur (--marquage)
}

// Causes de destruction transmises au rappel de destruction (ADR-005 : les
// horodatages de destruction alimentent le journal d'imputabilité).
const (
	// DestructionEcheance : l'ardoise a atteint son échéance (balayage ou
	// expiration paresseuse à la lecture).
	DestructionEcheance = "echeance"
	// DestructionLecture : destruction à la première lecture (EF-4).
	DestructionLecture = "lecture"
)

// RappelDestruction est appelé après la destruction effective d'une
// ardoise. Il ne reçoit que des métadonnées — identifiant serveur,
// empreinte du chiffré, cause — jamais le contenu. Il doit être rapide et
// ne jamais bloquer : il peut être invoqué depuis le balayage ou une
// lecture.
type RappelDestruction func(id, empreinte, cause string)

// NotifiantDestruction est l'interface optionnelle des magasins capables de
// signaler leurs destructions (journalisation, ADR-005). Le rappel se
// définit une seule fois, avant la mise en service du magasin.
type NotifiantDestruction interface {
	DefinirRappelDestruction(RappelDestruction)
}

// Magasin est le contrat commun des supports de conservation.
type Magasin interface {
	// Deposer conserve une ardoise. ErrExiste en cas de collision
	// d'identifiant.
	Deposer(a *Ardoise) error

	// Recuperer retourne l'ardoise si elle existe et n'est pas expirée.
	// Lorsque la destruction à la première lecture est active, la
	// consommation est atomique : parmi des lectures concurrentes, une
	// seule obtient le contenu, les autres reçoivent ErrIntrouvable.
	Recuperer(id string) (*Ardoise, error)

	// Fermer arrête le balayage d'expiration et libère les ressources du
	// magasin (clé de magasin comprise pour le support disque). Idempotent.
	Fermer() error
}
