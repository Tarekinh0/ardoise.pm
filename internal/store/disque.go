package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// versionEnregistrement est l'octet de version du format des fichiers du
// magasin sur disque.
const versionEnregistrement byte = 0x01

const (
	tailleCleMagasin   = 32
	tailleNonceMagasin = 12
	extension          = ".ard"
)

// Disque est le magasin sur disque chiffré (RET-3) : il survit à un
// redémarrage de l'instance. Chaque ardoise occupe un fichier propre sous
// le répertoire configuré (docs/man.md : /var/lib/ardoise/), chiffré
// intégralement — contenu ET métadonnées — en AES-256-GCM sous la clé de
// magasin (retention.cle_magasin). Rien n'est jamais écrit en clair : en
// mode aveugle le contenu est déjà du chiffré client, et l'enregistrement
// qui l'enveloppe (échéance, options, empreinte) est chiffré à son tour.
//
// L'identifiant de l'ardoise sert de données additionnelles authentifiées :
// un fichier renommé ou substitué ne se déchiffre pas. Les écritures sont
// atomiques (fichier temporaire, fsync, rename, fsync du répertoire). Un
// fichier corrompu ou illisible est traité comme absent (code 5) ; le
// balayage ne détruit que les enregistrements déchiffrables et expirés,
// jamais les fichiers illisibles — une clé de magasin mal configurée ne
// doit pas provoquer une destruction en masse.
type Disque struct {
	repertoire string
	aead       cipher.AEAD
	cle        []byte

	mu      sync.Mutex
	horloge func() time.Time
	arret   chan struct{}
	fermer  sync.Once

	// rappel, s'il est défini (une fois, avant mise en service), est
	// invoqué hors verrou après chaque destruction effective.
	rappel RappelDestruction
}

// DefinirRappelDestruction installe le rappel de destruction
// (NotifiantDestruction). À appeler avant la mise en service du magasin.
func (d *Disque) DefinirRappelDestruction(rappel RappelDestruction) {
	d.rappel = rappel
}

// notifier invoque le rappel pour une destruction, hors verrou.
func (d *Disque) notifier(id, empreinte, cause string) {
	if d.rappel != nil {
		d.rappel(id, empreinte, cause)
	}
}

// NouveauDisque ouvre (et crée au besoin) le répertoire du magasin, monte
// l'AEAD sous la clé de magasin (32 octets) et démarre le balayage
// d'expiration. La clé est copiée ; l'appelant peut effacer la sienne.
func NouveauDisque(ctx context.Context, repertoire string, cleMagasin []byte, periode time.Duration) (*Disque, error) {
	if len(cleMagasin) != tailleCleMagasin {
		return nil, fmt.Errorf("clé de magasin de %d octets, 32 requis", len(cleMagasin))
	}
	if err := os.MkdirAll(repertoire, 0o700); err != nil {
		return nil, fmt.Errorf("répertoire du magasin : %w", err)
	}
	cle := append([]byte(nil), cleMagasin...)
	bloc, err := aes.NewCipher(cle)
	if err != nil {
		return nil, fmt.Errorf("initialisation AES du magasin : %w", err)
	}
	aead, err := cipher.NewGCM(bloc)
	if err != nil {
		return nil, fmt.Errorf("initialisation GCM du magasin : %w", err)
	}
	d := &Disque{
		repertoire: repertoire,
		aead:       aead,
		cle:        cle,
		horloge:    time.Now,
		arret:      make(chan struct{}),
	}
	go d.balayer(ctx, periode)
	return d, nil
}

// enregistrement est la forme JSON d'une ardoise avant chiffrement.
type enregistrement struct {
	ID                 string    `json:"id"`
	Chiffre            []byte    `json:"chiffre"`
	Empreinte          string    `json:"empreinte"`
	Echeance           time.Time `json:"echeance"`
	LectureUnique      bool      `json:"lecture_unique"`
	MarquageComplement string    `json:"marquage_complement,omitempty"`
}

func (d *Disque) chemin(id string) string {
	return filepath.Join(d.repertoire, id+extension)
}

// Deposer écrit l'enregistrement chiffré de manière atomique : fichier
// temporaire dans le même répertoire, fsync, rename, fsync du répertoire.
func (d *Disque) Deposer(a *Ardoise) error {
	if !idSain(a.ID) {
		return errors.New("identifiant d'ardoise invalide pour le magasin sur disque")
	}
	clair, err := json.Marshal(enregistrement{
		ID:                 a.ID,
		Chiffre:            a.Chiffre,
		Empreinte:          a.Empreinte,
		Echeance:           a.Echeance,
		LectureUnique:      a.LectureUnique,
		MarquageComplement: a.MarquageComplement,
	})
	if err != nil {
		return fmt.Errorf("sérialisation de l'enregistrement : %w", err)
	}
	nonce := make([]byte, tailleNonceMagasin)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("génération du nonce de magasin : %w", err)
	}
	scelle := make([]byte, 0, 1+len(nonce)+len(clair)+d.aead.Overhead())
	scelle = append(scelle, versionEnregistrement)
	scelle = append(scelle, nonce...)
	scelle = d.aead.Seal(scelle, nonce, clair, []byte(a.ID))

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := os.Lstat(d.chemin(a.ID)); err == nil {
		return ErrExiste
	}
	return d.ecrireAtomique(d.chemin(a.ID), scelle)
}

// Recuperer lit et déchiffre l'enregistrement, applique l'expiration
// paresseuse puis la destruction à la première lecture. Le verrou rend la
// consommation atomique : une seule lecture concurrente obtient le contenu.
func (d *Disque) Recuperer(id string) (*Ardoise, error) {
	if !idSain(id) {
		return nil, ErrIntrouvable
	}
	d.mu.Lock()
	e, err := d.lire(id)
	if err != nil {
		d.mu.Unlock()
		return nil, ErrIntrouvable
	}
	if !d.horloge().Before(e.Echeance) {
		d.supprimer(id)
		d.mu.Unlock()
		d.notifier(id, e.Empreinte, DestructionEcheance)
		return nil, ErrIntrouvable
	}
	if e.LectureUnique {
		// Consommation avant restitution : la suppression du fichier est
		// le point de bascule, les lectures suivantes reçoivent code 5.
		if err := d.supprimer(id); err != nil {
			d.mu.Unlock()
			return nil, fmt.Errorf("consommation de l'ardoise : %w", err)
		}
		d.mu.Unlock()
		d.notifier(id, e.Empreinte, DestructionLecture)
	} else {
		d.mu.Unlock()
	}
	return &Ardoise{
		ID:                 e.ID,
		Chiffre:            e.Chiffre,
		Empreinte:          e.Empreinte,
		Echeance:           e.Echeance,
		LectureUnique:      e.LectureUnique,
		MarquageComplement: e.MarquageComplement,
	}, nil
}

// Fermer arrête le balayage et efface la clé de magasin.
func (d *Disque) Fermer() error {
	d.fermer.Do(func() {
		close(d.arret)
		for i := range d.cle {
			d.cle[i] = 0
		}
	})
	return nil
}

// lire déchiffre l'enregistrement de l'ardoise id. Toute anomalie —
// fichier absent, tronqué, altéré, clé de magasin inadaptée, identifiant ne
// correspondant pas au nom du fichier — est une erreur, que l'appelant
// traduit en ErrIntrouvable (code 5).
func (d *Disque) lire(id string) (*enregistrement, error) {
	donnees, err := os.ReadFile(d.chemin(id))
	if err != nil {
		return nil, err
	}
	if len(donnees) < 1+tailleNonceMagasin+d.aead.Overhead() || donnees[0] != versionEnregistrement {
		return nil, errors.New("enregistrement corrompu")
	}
	nonce := donnees[1 : 1+tailleNonceMagasin]
	clair, err := d.aead.Open(nil, nonce, donnees[1+tailleNonceMagasin:], []byte(id))
	if err != nil {
		return nil, errors.New("enregistrement indéchiffrable")
	}
	var e enregistrement
	if err := json.Unmarshal(clair, &e); err != nil {
		return nil, fmt.Errorf("enregistrement illisible : %w", err)
	}
	if e.ID != id {
		return nil, errors.New("enregistrement incohérent")
	}
	return &e, nil
}

func (d *Disque) supprimer(id string) error {
	if err := os.Remove(d.chemin(id)); err != nil {
		return err
	}
	return synchroniserRepertoire(d.repertoire)
}

func (d *Disque) ecrireAtomique(chemin string, donnees []byte) error {
	tmp, err := os.CreateTemp(d.repertoire, ".depot-*")
	if err != nil {
		return fmt.Errorf("écriture du magasin : %w", err)
	}
	nettoyer := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return nettoyer(fmt.Errorf("droits du fichier de magasin : %w", err))
	}
	if _, err := tmp.Write(donnees); err != nil {
		return nettoyer(fmt.Errorf("écriture du magasin : %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return nettoyer(fmt.Errorf("synchronisation du magasin : %w", err))
	}
	if err := tmp.Close(); err != nil {
		return nettoyer(fmt.Errorf("écriture du magasin : %w", err))
	}
	if err := os.Rename(tmp.Name(), chemin); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("écriture du magasin : %w", err)
	}
	return synchroniserRepertoire(d.repertoire)
}

// synchroniserRepertoire force l'écriture des métadonnées du répertoire,
// afin que création et suppression survivent à une coupure.
func synchroniserRepertoire(repertoire string) error {
	rep, err := os.Open(repertoire)
	if err != nil {
		return err
	}
	defer rep.Close()
	return rep.Sync()
}

func (d *Disque) balayer(ctx context.Context, periode time.Duration) {
	ticker := time.NewTicker(periode)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-d.arret:
			return
		case <-ticker.C:
			d.purgerExpirees()
		}
	}
}

// purgerExpirees détruit les enregistrements déchiffrables et expirés. Les
// fichiers illisibles sont laissés en place (voir le commentaire de type) ;
// les fichiers temporaires abandonnés de plus d'une heure sont nettoyés.
func (d *Disque) purgerExpirees() {
	entrees, err := os.ReadDir(d.repertoire)
	if err != nil {
		return
	}
	maintenant := d.horloge()
	for _, entree := range entrees {
		nom := entree.Name()
		switch {
		case strings.HasSuffix(nom, extension):
			id := strings.TrimSuffix(nom, extension)
			if !idSain(id) {
				continue
			}
			d.mu.Lock()
			e, err := d.lire(id)
			expiree := err == nil && !maintenant.Before(e.Echeance)
			if expiree {
				d.supprimer(id)
			}
			d.mu.Unlock()
			if expiree {
				d.notifier(id, e.Empreinte, DestructionEcheance)
			}
		case strings.HasPrefix(nom, ".depot-"):
			if infos, err := entree.Info(); err == nil && maintenant.Sub(infos.ModTime()) > time.Hour {
				os.Remove(filepath.Join(d.repertoire, nom))
			}
		}
	}
}

// idSain garde le nom de fichier dans l'alphabet des identifiants serveur
// ([a-z2-9], docs/dat.md §4.3) : aucune traversée de chemin possible.
func idSain(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '9') {
			return false
		}
	}
	return true
}

// ChargerCleMagasin lit la clé de magasin (retention.cle_magasin) : un
// fichier contenant soit 32 octets bruts, soit 64 caractères hexadécimaux.
// Le fichier doit appartenir au seul exploitant : tout droit de groupe ou
// d'autrui est refusé.
func ChargerCleMagasin(chemin string) ([]byte, error) {
	infos, err := os.Stat(chemin)
	if err != nil {
		return nil, fmt.Errorf("clé de magasin : %w", err)
	}
	if mode := infos.Mode(); mode&fs.ModeType != 0 || mode.Perm()&0o077 != 0 {
		return nil, fmt.Errorf("clé de magasin %s : droits %v trop ouverts (0600 au plus, aucun droit de groupe ni d'autrui)", chemin, infos.Mode().Perm())
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("clé de magasin : %w", err)
	}
	defer func() {
		for i := range donnees {
			donnees[i] = 0
		}
	}()
	if len(donnees) == tailleCleMagasin {
		return append([]byte(nil), donnees...), nil
	}
	// Forme hexadécimale : décodage sans jamais convertir le matériel de clé
	// en chaîne (invariant []byte, docs/dat.md annexe B).
	texte := bytes.TrimSpace(donnees)
	if len(texte) == 2*tailleCleMagasin {
		cle := make([]byte, tailleCleMagasin)
		if _, err := hex.Decode(cle, texte); err == nil {
			return cle, nil
		}
	}
	return nil, fmt.Errorf("clé de magasin %s : 32 octets bruts ou 64 caractères hexadécimaux attendus", chemin)
}
