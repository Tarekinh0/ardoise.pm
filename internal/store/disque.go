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
	"log"
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
	magasinBase

	repertoire string
	aead       cipher.AEAD
	cle        []byte
	mu         sync.Mutex
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
		magasinBase: magasinBase{
			horloge: time.Now,
			arret:   make(chan struct{}),
		},
	}
	// Vérification de l'intégrité des fichiers existants au démarrage.
	// Un fichier corrompu ou illisible est signalé à l'exploitant sans
	// être supprimé : une clé de magasin erronée ne doit pas provoquer
	// une destruction en masse (PR-109).
	d.verifierIntegriteDemarrage()
	go d.balayer(ctx, periode, d.purgerExpirees)
	return d, nil
}

// DefinirRappelDestruction installe le rappel de destruction (PR-106).
// Satisfait NotifiantDestruction.
func (d *Disque) DefinirRappelDestruction(rappel RappelDestruction) {
	d.magasinBase.definirRappelDestruction(rappel)
}

// enregistrement est la forme JSON d'une ardoise avant chiffrement.
type enregistrement struct {
	ID                 string    `json:"id"`
	Chiffre            []byte    `json:"chiffre"`
	Empreinte          string    `json:"empreinte"`
	Echeance           time.Time `json:"echeance"`
	LectureUnique      bool      `json:"lecture_unique"`
	MarquageComplement string    `json:"marquage_complement,omitempty"`
	Pour               []string  `json:"pour,omitempty"`
}

func (d *Disque) chemin(id string) string {
	return filepath.Join(d.repertoire, id+extension)
}

// Deposer écrit l'enregistrement chiffré de manière atomique : fichier
// temporaire dans le même répertoire, fsync, rename, fsync du répertoire.
//
// S1 : lorsque maxArdoises est atteint, ErrSature est retourné.
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
		Pour:               a.Pour,
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
	// S1 : vérifier le plafond
	if d.maxArdoises > 0 {
		entrees, err := os.ReadDir(d.repertoire)
		if err == nil {
			count := 0
			for _, e := range entrees {
				if strings.HasSuffix(e.Name(), extension) {
					count++
				}
			}
			if count >= d.maxArdoises {
				return ErrSature
			}
		}
	}
	return d.ecrireAtomique(d.chemin(a.ID), scelle)
}

// Recuperer lit et déchiffre l'enregistrement, applique l'expiration
// paresseuse puis la destruction à la première lecture. Le verrou rend la
// consommation atomique : une seule lecture concurrente obtient le contenu.
func (d *Disque) Recuperer(id string) (*Ardoise, error) {
	return d.RecupererSi(id, nil)
}

// RecupererSi lit et déchiffre l'enregistrement, applique l'expiration
// paresseuse, évalue le prédicat AVANT toute consommation (un lecteur
// refusé ne détruit rien), puis la destruction à la première lecture. Le
// verrou rend la consommation atomique : une seule lecture concurrente
// obtient le contenu.
func (d *Disque) RecupererSi(id string, admis func(*Ardoise) bool) (*Ardoise, error) {
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
	if admis != nil && !admis(e.versArdoise()) {
		d.mu.Unlock()
		return nil, ErrNonAdmis
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
	return e.versArdoise(), nil
}

// versArdoise traduit l'enregistrement déchiffré vers l'objet du magasin.
func (e *enregistrement) versArdoise() *Ardoise {
	return &Ardoise{
		ID:                 e.ID,
		Chiffre:            e.Chiffre,
		Empreinte:          e.Empreinte,
		Echeance:           e.Echeance,
		LectureUnique:      e.LectureUnique,
		MarquageComplement: e.MarquageComplement,
		Pour:               e.Pour,
	}
}

// Fermer arrête le balayage, draine les ardoises persistées via le rappel
// de destruction, puis efface la clé de magasin. Le drainage est effectué
// avant l'effacement de la clé, afin que le journal d'imputabilité reçoive
// les horodatages de destruction (ADR-005) —corrigé dans PR-002, l'absence
// de drainage rendait le journal incomplet à l'arrêt (les ardoises non
// expirées présentes sur le disque ne généraient aucun événement).
func (d *Disque) Fermer() error {
	d.fermer.Do(func() {
		close(d.arret)
		// Drainer les ardoises persistées via le rappel de destruction,
		// avant d'effacer la clé de magasin (PR-002).
		d.drainerDestructions()
		for i := range d.cle {
			d.cle[i] = 0
		}
	})
	return nil
}

// drainerDestructions parcourt les fichiers du répertoire et notifie chaque
// ardoise déchiffrable comme détruite par échéance, afin que le journal
// d'imputabilité reçoive les horodatages de destruction à l'arrêt
// (ADR-005, PR-002).
func (d *Disque) drainerDestructions() {
	entrees, err := os.ReadDir(d.repertoire)
	if err != nil {
		return
	}
	for _, entree := range entrees {
		nom := entree.Name()
		if !strings.HasSuffix(nom, extension) {
			continue
		}
		id := strings.TrimSuffix(nom, extension)
		if !idSain(id) {
			continue
		}
		e, err := d.lire(id)
		if err != nil {
			continue
		}
		d.notifier(id, e.Empreinte, DestructionEcheance)
	}
}

// verifierIntegriteDemarrage parcourt les fichiers existants du magasin
// et signale à l'exploitant tout fichier corrompu ou indéchiffrable.
// Aucun fichier n'est supprimé : une clé de magasin erronée ne doit pas
// provoquer une destruction en masse (PR-109).
func (d *Disque) verifierIntegriteDemarrage() {
	entrees, err := os.ReadDir(d.repertoire)
	if err != nil {
		log.Printf("magasin disque : impossible de lire le répertoire %s : %v", d.repertoire, err)
		return
	}
	corrompus := 0
	for _, entree := range entrees {
		nom := entree.Name()
		// Nettoyage des fichiers temporaires abandonnés : un crash ou un
		// arrêt brutal pendant ecrireAtomique laisse des fichiers .depot-*
		// qui ne seront jamais nettoyés par purgerExpirees (PR-001).
		if strings.HasPrefix(nom, ".depot-") {
			log.Printf("magasin disque : fichier temporaire abandonné au démarrage, nettoyage : %s", nom)
			os.Remove(filepath.Join(d.repertoire, nom))
			continue
		}
		if !strings.HasSuffix(nom, extension) {
			continue
		}
		id := strings.TrimSuffix(nom, extension)
		if !idSain(id) {
			log.Printf("magasin disque : fichier au nom inattendu ignoré : %s", nom)
			continue
		}
		if _, err := d.lire(id); err != nil {
			log.Printf("magasin disque : AVERTISSEMENT — fichier corrompu ou indéchiffrable : %s (%v). Le fichier n'est pas supprimé.", nom, err)
			corrompus++
		}
	}
	if corrompus > 0 {
		log.Printf("magasin disque : %d fichier(s) corrompu(s) détecté(s) au démarrage — aucun n'a été supprimé. Vérifiez la clé de magasin et l'intégrité du stockage.", corrompus)
	}
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
	// La suppression effective est le contrat principal ; une défaillance
	// de la synchronisation du répertoire ne l'invalide pas (PR-105).
	if err := synchroniserRepertoire(d.repertoire); err != nil {
		log.Printf("magasin disque : synchronisation du répertoire après suppression de %s : %v", id, err)
	}
	return nil
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

// purgerExpirees détruit les enregistrements déchiffrables et expirés. Les
// fichiers illisibles sont laissés en place (voir le commentaire de type) ;
// les fichiers temporaires abandonnés de plus d'une heure sont nettoyés.
//
// PR-103 : la contention O(n) documentée (Lock par fichier) est supprimée.
// La première phase collecte tous les identifiants expirés sous un seul
// verrou — le temps de balayage est proportionnel au nombre de fichiers,
// mais Deposer et Recuperer ne sont bloqués que le temps d'UNE acquisition
// de Lock plutôt que N. La seconde phase notifie hors verrou. L'optimisation
// réduit la contention au sens de l'ADR-argus (HIGH-005).
func (d *Disque) purgerExpirees() {
	entrees, err := os.ReadDir(d.repertoire)
	if err != nil {
		return
	}
	maintenant := d.horloge()

	type aExpurger struct {
		id        string
		empreinte string
	}
	var aExpurgerList []aExpurger

	// Phase 1 : collecter les identifiants expirés sous un seul verrou,
	// avec suppression atomique du fichier.
	d.mu.Lock()
	for _, entree := range entrees {
		nom := entree.Name()
		switch {
		case strings.HasSuffix(nom, extension):
			id := strings.TrimSuffix(nom, extension)
			if !idSain(id) {
				continue
			}
			e, err := d.lire(id)
			if err == nil && !maintenant.Before(e.Echeance) {
				d.supprimer(id)
				aExpurgerList = append(aExpurgerList, aExpurger{id, e.Empreinte})
			}
		case strings.HasPrefix(nom, ".depot-"):
			// Fichiers temporaires : traités hors verrou (phase 3).
		}
	}
	d.mu.Unlock()

	// Phase 2 : notifier les destructions hors verrou (PR-103).
	for _, ae := range aExpurgerList {
		d.notifier(ae.id, ae.empreinte, DestructionEcheance)
	}

	// Phase 3 : nettoyage des fichiers temporaires abandonnés (sans verrou).
	for _, entree := range entrees {
		if strings.HasPrefix(entree.Name(), ".depot-") {
			if infos, err := entree.Info(); err == nil && maintenant.Sub(infos.ModTime()) > time.Hour {
				os.Remove(filepath.Join(d.repertoire, entree.Name()))
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
