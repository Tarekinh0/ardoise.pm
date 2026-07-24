// Package journal porte la journalisation d'imputabilité de l'instance
// (docs/dat.md §5.6, ADR-005) : JOURN-1 (collecteur syslog+TLS, entrées
// chaînées), JOURN-2 (collecteur syslog+TLS), JOURN-3 (fichier local,
// collecte périodique), JOURN-4 (aucune journalisation).
//
// # Métadonnées seulement (ADR-005)
//
// Une entrée consigne des actes, jamais des contenus : identité de
// l'émetteur et mécanisme d'identification (marqué déclaratif sous AUTH-4),
// horodatages, empreinte SHA-256 du chiffré, instance et niveau de marquage.
// Aucun contenu, aucune clé, aucun mot de passe, aucun identifiant complet.
//
// L'identifiant SERVEUR d'une ardoise figure en revanche dans les entrées,
// et ce choix est délibéré : l'identifiant complet au sens de l'ADR-005 est
// « <id-serveur>#<clé> », et le fragment de clé ne parvient JAMAIS au
// serveur (mode aveugle) ou n'y survit pas à la réponse de dépôt (mode
// analysé) — le serveur ne peut donc pas consigner ce qu'il ne détient pas.
// L'identifiant serveur seul n'ouvre aucun contenu (il faut le fragment) et
// c'est lui qui permet de corréler dépôt, lecture et destruction d'une même
// ardoise dans le journal — précisément la fonction d'imputabilité que
// l'ADR-005 assigne au journal (attaquant A8 : les journaux ne contiennent
// ni contenu, ni clé, ni identifiant complet — l'identifiant serveur n'est
// aucun des trois).
//
// # Émission non bloquante
//
// L'émission est asynchrone : un canal borné alimente une unique goroutine
// d'écriture. Un collecteur lent ou injoignable ne retarde ni ne fait
// échouer aucune opération d'utilisateur. En contrepartie, lorsque le canal
// déborde, les entrées les PLUS ANCIENNES sont abandonnées (avec compteur
// et avertissement sur la sortie d'erreur) : la disponibilité du service
// prime sur la complétude du journal — la disponibilité de l'acheminement
// des métadonnées (annexe A.1) relève de la supervision de l'entité, à qui
// le compteur d'abandons donne prise. Fermer vide le canal avant de rendre
// la main (arrêt propre).
//
// # Chaînage (JOURN-1)
//
// Chaque entrée porte « chaine » : l'empreinte SHA-256 hexadécimale de
// (JSON canonique de l'entrée précédente ‖ JSON de l'entrée courante sans
// son champ chaine). La genèse est l'empreinte du couple {nom d'instance,
// horodatage de démarrage} : toute altération, suppression ou réordonnance
// d'entrée casse la chaîne à la vérification (annexe B, journaux chaînés).
// L'état de chaîne vit en mémoire : chaque démarrage du processus ouvre un
// nouveau segment ancré sur son propre horodatage de genèse — la continuité
// entre segments s'apprécie côté collecteur (limitation documentée : un
// arrêt du processus clôt un segment, il ne casse pas la détection
// d'altération à l'intérieur de chacun).
package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Événements consignés (ADR-005 : horodatages de création, de lecture et de
// destruction ; refus d'analyse et d'accès).
const (
	EvenementDepot               = "depot"
	EvenementLecture             = "lecture"
	EvenementDestructionEcheance = "destruction_echeance"
	EvenementDestructionLecture  = "destruction_lecture"
	EvenementDepotRefuseAnalyse  = "depot_refuse_analyse"
	EvenementAccesRefuse         = "acces_refuse"
)

// Identite est l'identité consignée avec son mécanisme : la force probante
// de l'entrée se lit dans l'entrée elle-même — « declaratif » à vrai marque
// une identité non authentifiée qui ne fonde aucune imputabilité opposable
// (ADR-005, AUTH-4).
type Identite struct {
	Utilisateur string `json:"utilisateur,omitempty"`
	Hote        string `json:"hote,omitempty"`
	Mecanisme   string `json:"mecanisme,omitempty"`
	Declaratif  bool   `json:"declaratif"`
}

// Entree est une entrée de journal : des métadonnées d'imputabilité,
// exclusivement (voir le commentaire de paquet). Horodatage, Instance et
// Niveau sont renseignés par Consigner.
type Entree struct {
	Horodatage string    `json:"horodatage"` // RFC 3339
	Evenement  string    `json:"evenement"`
	Instance   string    `json:"instance"`
	Niveau     string    `json:"niveau,omitempty"` // libellé de marquage de l'instance
	Identite   *Identite `json:"identite,omitempty"`
	IDServeur  string    `json:"id_serveur,omitempty"` // jamais le fragment de clé
	Empreinte  string    `json:"empreinte,omitempty"`  // SHA-256 du chiffré
	Echeance   string    `json:"echeance,omitempty"`   // RFC 3339
	Chaine     string    `json:"chaine,omitempty"`     // JOURN-1
}

// Config décrit le journal à monter, depuis la section [journal] de la
// configuration d'instance.
type Config struct {
	Instance    string // instance.nom — aussi matière de la genèse de chaîne
	Niveau      string // marquage.libelle si le marquage est actif
	Destination string // "aucun" | "fichier" | "syslog+tls://hôte:port"
	Chainage    bool   // JOURN-1
	Fichier     string // journal.fichier — requis si destination "fichier"
	AC          string // journal.ac — AC du collecteur (PEM), défaut : magasin système
	Stderr      io.Writer
}

// formatHorodatage est le format des horodatages d'entrée : RFC 3339 en
// UTC, précision microseconde — également valide comme TIMESTAMP RFC 5424.
const formatHorodatage = "2006-01-02T15:04:05.000000Z07:00"

// tailleFile est la capacité du canal d'émission ; au-delà, les entrées les
// plus anciennes sont abandonnées (voir le commentaire de paquet).
const tailleFile = 256

// puits est la destination physique des entrées sérialisées.
type puits interface {
	emettre(e *Entree, canonique []byte) error
	fermer() error
}

// Journal émet les entrées d'imputabilité. Un Journal nil (JOURN-4) est
// valide : Consigner et Fermer n'y font rien — aucune émission, nulle part.
type Journal struct {
	instance string
	niveau   string
	chainage bool
	puits    puits
	stderr   io.Writer

	mu      sync.RWMutex
	ferme   bool
	entrees chan *Entree
	fini    chan struct{}

	compteurMu sync.Mutex
	abandons   int
	echecs     int

	// ancrage est le JSON canonique de genèse du segment de chaîne de ce
	// processus ; dernier est celui de la dernière entrée émise (ou
	// l'ancrage), état du chaînage — manipulé par la seule goroutine
	// d'écriture.
	ancrage []byte
	dernier []byte
}

// Nouveau monte le journal déclaré par la configuration. Pour JOURN-4
// (« aucun »), le Journal retourné est nil : aucune émission. L'erreur ne
// concerne que le montage (fichier inaccessible, AC illisible, destination
// inconnue) : après démarrage, aucun échec d'émission ne remonte jamais
// vers les opérations.
func Nouveau(cfg Config) (*Journal, error) {
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	var p puits
	var err error
	switch {
	case cfg.Destination == "aucun" || cfg.Destination == "":
		return nil, nil // JOURN-4 : zéro émission
	case cfg.Destination == "fichier":
		p, err = nouveauPuitsFichier(cfg.Fichier)
	case estSyslogTLS(cfg.Destination):
		p, err = nouveauPuitsSyslogTLS(cfg.Destination, cfg.AC, cfg.Instance)
	default:
		return nil, fmt.Errorf("journal.destination « %s » inconnue", cfg.Destination)
	}
	if err != nil {
		return nil, err
	}
	ancrage := genese(cfg.Instance, time.Now())
	j := &Journal{
		instance: cfg.Instance,
		niveau:   cfg.Niveau,
		chainage: cfg.Chainage,
		puits:    p,
		stderr:   cfg.Stderr,
		entrees:  make(chan *Entree, tailleFile),
		fini:     make(chan struct{}),
		ancrage:  ancrage,
		dernier:  ancrage,
	}
	go j.ecrire()
	return j, nil
}

// Ancrage restitue le JSON canonique de genèse du segment de chaîne de ce
// processus : le point de départ que VerifierChaine attend.
func (j *Journal) Ancrage() []byte {
	if j == nil {
		return nil
	}
	return append([]byte(nil), j.ancrage...)
}

// genese produit le JSON canonique d'ancrage de la chaîne : nom d'instance
// et horodatage de démarrage du processus (voir le commentaire de paquet).
func genese(instance string, demarrage time.Time) []byte {
	donnees, _ := json.Marshal(struct {
		Genese    string `json:"genese"`
		Demarrage string `json:"demarrage"`
	}{instance, demarrage.UTC().Format(formatHorodatage)})
	return donnees
}

// Consigner soumet une entrée à l'émission, sans jamais bloquer : si la
// file est pleine, l'entrée la plus ancienne est abandonnée (compteur et
// avertissement). Horodatage, Instance et Niveau sont renseignés s'ils sont
// vides. Sur un Journal nil (JOURN-4), ne fait rien.
func (j *Journal) Consigner(e Entree) {
	if j == nil {
		return
	}
	if e.Horodatage == "" {
		e.Horodatage = time.Now().UTC().Format(formatHorodatage)
	}
	if e.Instance == "" {
		e.Instance = j.instance
	}
	if e.Niveau == "" {
		e.Niveau = j.niveau
	}
	j.mu.RLock()
	defer j.mu.RUnlock()
	if j.ferme {
		return
	}
	select {
	case j.entrees <- &e:
		return
	default:
	}
	// File pleine : abandon de la plus ancienne, au profit de la plus
	// récente (disponibilité du service avant complétude du journal).
	select {
	case <-j.entrees:
	default:
	}
	select {
	case j.entrees <- &e:
	default:
	}
	j.compteurMu.Lock()
	j.abandons++
	n := j.abandons
	j.compteurMu.Unlock()
	fmt.Fprintf(j.stderr, "ardoise : journal : file d'émission saturée, entrée la plus ancienne abandonnée (%d abandon(s) depuis le démarrage)\n", n)
}

// Abandons retourne le nombre d'entrées abandonnées depuis le démarrage.
func (j *Journal) Abandons() int {
	if j == nil {
		return 0
	}
	j.compteurMu.Lock()
	defer j.compteurMu.Unlock()
	return j.abandons
}

// Fermer draine la file, émet ce qui peut l'être, puis ferme le puits.
// Idempotent. Sur un Journal nil, ne fait rien.
func (j *Journal) Fermer() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	if j.ferme {
		j.mu.Unlock()
		<-j.fini
		return nil
	}
	j.ferme = true
	close(j.entrees)
	j.mu.Unlock()
	<-j.fini
	return j.puits.fermer()
}

// ecrire est l'unique goroutine d'écriture : chaînage, sérialisation,
// émission. Un échec d'émission est compté et signalé, jamais propagé —
// l'opération de l'utilisateur est déjà terminée.
func (j *Journal) ecrire() {
	defer close(j.fini)
	for e := range j.entrees {
		canonique, err := j.sceller(e)
		if err == nil {
			err = j.puits.emettre(e, canonique)
		}
		if err != nil {
			j.compteurMu.Lock()
			j.echecs++
			n := j.echecs
			j.compteurMu.Unlock()
			// Le message ne reproduit jamais l'entrée : seule la nature de
			// l'échec sort.
			fmt.Fprintf(j.stderr, "ardoise : journal : émission impossible (%d échec(s) depuis le démarrage) : %v\n", n, err)
		}
	}
}

// sceller applique le chaînage (JOURN-1) puis sérialise l'entrée. Sans
// chaînage, la sérialisation est directe.
func (j *Journal) sceller(e *Entree) ([]byte, error) {
	if !j.chainage {
		return json.Marshal(e)
	}
	e.Chaine = ""
	sans, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(j.dernier)
	h.Write(sans)
	e.Chaine = hex.EncodeToString(h.Sum(nil))
	canonique, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	j.dernier = canonique
	return canonique, nil
}

// VerifierChaine rejoue le chaînage sur une suite d'entrées sérialisées
// (JSON canonique, dans l'ordre d'émission) ancrée sur la genèse fournie,
// et retourne l'indice de la première entrée dont le champ « chaine » ne
// correspond pas (-1 si la chaîne est intègre). Outil de vérification pour
// les tests et les collecteurs.
func VerifierChaine(geneseCanonique []byte, entrees [][]byte) (int, error) {
	dernier := geneseCanonique
	for i, canonique := range entrees {
		var e Entree
		if err := json.Unmarshal(canonique, &e); err != nil {
			return i, fmt.Errorf("entrée %d illisible : %w", i, err)
		}
		attendue := e.Chaine
		e.Chaine = ""
		sans, err := json.Marshal(&e)
		if err != nil {
			return i, err
		}
		h := sha256.New()
		h.Write(dernier)
		h.Write(sans)
		if hex.EncodeToString(h.Sum(nil)) != attendue {
			return i, nil
		}
		dernier = canonique
	}
	return -1, nil
}

// Genese expose le JSON canonique d'ancrage pour un couple {instance,
// démarrage} donné — nécessaire à la vérification de chaîne.
func Genese(instance string, demarrage time.Time) []byte {
	return genese(instance, demarrage)
}

// estSyslogTLS reconnaît une destination de collecteur central.
func estSyslogTLS(destination string) bool {
	return len(destination) > len("syslog+tls://") && destination[:len("syslog+tls://")] == "syslog+tls://"
}
