package client

// Cache local du poste (docs/dat.md §5.9, ADR-013) : le contenu CHIFFRÉ tel
// que reçu de l'instance, indexé par l'empreinte de l'identifiant serveur —
// SHA-256 hexadécimale de l'identifiant, qui nomme les fichiers. La clé
// demeure dans l'identifiant détenu par l'utilisateur : AUCUN matériel de
// clé, aucun clair, aucun identifiant n'est jamais écrit — sans
// l'identifiant correspondant, le cache est inexploitable (docs/man.md,
// SÉCURITÉ).
//
// Chaque entrée occupe deux fichiers en 0600 dans un répertoire en 0700 :
//
//	<sha256(id)>.chiffre  le chiffré, octet pour octet tel que reçu
//	<sha256(id)>.meta     les métadonnées JSON : échéance, empreinte du
//	                      chiffré, politique de cache déclarée par
//	                      l'instance à l'écriture, champs de marquage
//
// La POLITIQUE VOYAGE AVEC L'ENTRÉE : le fichier .meta consigne la
// politique servie par l'instance au moment de l'écriture (« borne » ou
// « libre »), et c'est elle qui gouverne les lectures ultérieures — en
// particulier hors ligne (« --cache-seul »), où l'instance est
// injoignable : une lecture différée ne peut jamais excéder ce que
// l'instance avait accordé (ADR-013 : le client ne peut pas outrepasser
// l'autorisation du serveur).
//
//   - « interdit » (CACHE-1) : aucune entrée n'est jamais écrite ni lue ;
//   - « borne » (CACHE-2) : l'entrée expire à l'échéance de l'ardoise,
//     jamais au-delà ; toute entrée expirée est purgée d'office au premier
//     accès au cache (purge opportuniste) ;
//   - « libre » (CACHE-3) : l'entrée ne porte pas d'échéance propre et
//     n'est purgée que sur demande de l'utilisateur (« ardoise purge »).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Politiques de rémanence déclarées par l'instance (docs/dat.md §5.9).
const (
	CacheInterdit = "interdit" // CACHE-1
	CacheBorne    = "borne"    // CACHE-2
	CacheLibre    = "libre"    // CACHE-3
)

// Extensions des fichiers d'entrée du cache.
const (
	extensionChiffre = ".chiffre"
	extensionMeta    = ".meta"
)

// ErrCacheAbsent est l'unique erreur de lecture du cache : l'entrée
// n'existe pas, est expirée ou est illisible — indistinguables, comme au
// serveur (code 5).
var ErrCacheAbsent = errors.New("ardoise absente du cache local ou expirée")

// EntreeCache est une entrée restituée par Lire : le chiffré tel que reçu
// et les métadonnées du fichier .meta.
type EntreeCache struct {
	Chiffre   []byte
	Empreinte string   // SHA-256 hexadécimale du chiffré, telle qu'annoncée
	Echeance  string   // RFC 3339 ; vide sous la politique « libre »
	Politique string   // politique déclarée par l'instance à l'écriture
	Marquage  Marquage // champs de marquage servis par l'instance
}

// metaCache est la forme JSON du fichier .meta.
type metaCache struct {
	Echeance  string   `json:"echeance,omitempty"`
	Empreinte string   `json:"empreinte"`
	Politique string   `json:"politique"`
	Marquage  Marquage `json:"marquage"`
}

// Cache est le cache local d'un poste, enraciné dans un répertoire.
type Cache struct {
	repertoire string
	horloge    func() time.Time
}

// NouveauCache prépare le cache au répertoire donné, sans le créer : la
// création n'intervient qu'à la première écriture.
func NouveauCache(repertoire string) *Cache {
	return &Cache{repertoire: repertoire, horloge: time.Now}
}

// nomEntree retourne le nom de fichier (sans extension) d'un identifiant
// serveur : son empreinte SHA-256 hexadécimale (ADR-013 : « indexé par
// l'empreinte de l'identifiant serveur »).
func nomEntree(id string) string {
	empreinte := sha256.Sum256([]byte(id))
	return hex.EncodeToString(empreinte[:])
}

// Ecrire conserve une entrée sous la politique déclarée par l'instance :
// « borne » consigne l'échéance de l'ardoise (l'entrée ne survivra jamais
// au-delà), « libre » n'en consigne aucune, « interdit » est un refus.
// L'écriture purge d'office les entrées expirées (purge opportuniste).
func (c *Cache) Ecrire(id, politique string, reponse *ReponseArdoise) error {
	switch politique {
	case CacheBorne, CacheLibre:
	default:
		return fmt.Errorf("politique de cache « %s » : aucune écriture admise", politique)
	}
	if err := os.MkdirAll(c.repertoire, 0o700); err != nil {
		return fmt.Errorf("répertoire du cache : %w", err)
	}
	c.purgerOpportuniste()

	meta := metaCache{
		Empreinte: reponse.Empreinte,
		Politique: politique,
		Marquage:  reponse.Marquage,
	}
	if politique == CacheBorne {
		meta.Echeance = reponse.Echeance
	}
	donneesMeta, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("métadonnées du cache : %w", err)
	}
	nom := nomEntree(id)
	if err := ecrirePrive(filepath.Join(c.repertoire, nom+extensionChiffre), reponse.Chiffre); err != nil {
		return fmt.Errorf("écriture du cache : %w", err)
	}
	if err := ecrirePrive(filepath.Join(c.repertoire, nom+extensionMeta), donneesMeta); err != nil {
		os.Remove(filepath.Join(c.repertoire, nom+extensionChiffre))
		return fmt.Errorf("écriture du cache : %w", err)
	}
	return nil
}

// Lire restitue l'entrée d'un identifiant serveur. La politique consignée
// dans l'entrée gouverne la lecture : sous « borne », une entrée dont
// l'échéance est atteinte est détruite et la lecture échoue — y compris
// hors ligne, la politique voyageant avec l'entrée (voir le commentaire de
// paquet). Toute anomalie répond ErrCacheAbsent, sans distinction. La
// lecture purge d'office les entrées expirées (purge opportuniste).
func (c *Cache) Lire(id string) (*EntreeCache, error) {
	c.purgerOpportuniste()
	nom := nomEntree(id)
	donneesMeta, err := os.ReadFile(filepath.Join(c.repertoire, nom+extensionMeta))
	if err != nil {
		return nil, ErrCacheAbsent
	}
	var meta metaCache
	if err := json.Unmarshal(donneesMeta, &meta); err != nil {
		return nil, ErrCacheAbsent
	}
	if c.entreeExpiree(&meta) {
		c.supprimerEntree(nom)
		return nil, ErrCacheAbsent
	}
	chiffre, err := os.ReadFile(filepath.Join(c.repertoire, nom+extensionChiffre))
	if err != nil {
		return nil, ErrCacheAbsent
	}
	return &EntreeCache{
		Chiffre:   chiffre,
		Empreinte: meta.Empreinte,
		Echeance:  meta.Echeance,
		Politique: meta.Politique,
		Marquage:  meta.Marquage,
	}, nil
}

// entreeExpiree applique la politique consignée : sous « borne », l'entrée
// expire à son échéance ; sous « libre », jamais. Une entrée « borne »
// sans échéance lisible est traitée comme expirée (prudence).
func (c *Cache) entreeExpiree(meta *metaCache) bool {
	if meta.Politique == CacheLibre {
		return false
	}
	echeance, err := time.Parse(time.RFC3339, meta.Echeance)
	if err != nil {
		return true
	}
	return !c.horloge().Before(echeance)
}

// PurgerExpirees détruit les entrées expirées (politique « borne » dont
// l'échéance est atteinte, et entrées illisibles) et conserve le reste —
// les entrées « libre », sans échéance propre, ne sont jamais concernées
// (CACHE-3 : purge sur demande seulement, via PurgerTout). Un répertoire
// absent n'est pas une erreur : rien à purger.
func (c *Cache) PurgerExpirees() (supprimees, conservees int, err error) {
	entrees, err := os.ReadDir(c.repertoire)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("lecture du cache : %w", err)
	}
	for _, entree := range entrees {
		nom := entree.Name()
		if !strings.HasSuffix(nom, extensionMeta) {
			continue
		}
		base := strings.TrimSuffix(nom, extensionMeta)
		donneesMeta, errLecture := os.ReadFile(filepath.Join(c.repertoire, nom))
		var meta metaCache
		if errLecture != nil || json.Unmarshal(donneesMeta, &meta) != nil || c.entreeExpiree(&meta) {
			c.supprimerEntree(base)
			supprimees++
			continue
		}
		conservees++
	}
	return supprimees, conservees, nil
}

// PurgerTout détruit toutes les entrées, expirées ou non (« purge --tout »).
// Un répertoire absent n'est pas une erreur : rien à purger.
func (c *Cache) PurgerTout() (supprimees int, err error) {
	entrees, err := os.ReadDir(c.repertoire)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("lecture du cache : %w", err)
	}
	for _, entree := range entrees {
		nom := entree.Name()
		if !strings.HasSuffix(nom, extensionMeta) {
			continue
		}
		c.supprimerEntree(strings.TrimSuffix(nom, extensionMeta))
		supprimees++
	}
	return supprimees, nil
}

// purgerOpportuniste purge les entrées expirées sans propager d'erreur :
// tout accès au cache garantit qu'aucune entrée « borne » ne survit à son
// échéance (ADR-013), sans jamais faire échouer l'opération porteuse.
func (c *Cache) purgerOpportuniste() {
	_, _, _ = c.PurgerExpirees()
}

// supprimerEntree retire les deux fichiers d'une entrée.
func (c *Cache) supprimerEntree(base string) {
	os.Remove(filepath.Join(c.repertoire, base+extensionChiffre))
	os.Remove(filepath.Join(c.repertoire, base+extensionMeta))
}

// ecrirePrive écrit un fichier aux droits 0600, par fichier temporaire et
// renommage : jamais d'entrée partiellement écrite.
func ecrirePrive(chemin string, donnees []byte) error {
	repertoire := filepath.Dir(chemin)
	tmp, err := os.CreateTemp(repertoire, ".cache-*")
	if err != nil {
		return err
	}
	nettoyer := func(err error) error {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return nettoyer(err)
	}
	if _, err := tmp.Write(donnees); err != nil {
		return nettoyer(err)
	}
	if err := tmp.Close(); err != nil {
		return nettoyer(err)
	}
	if err := os.Rename(tmp.Name(), chemin); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
