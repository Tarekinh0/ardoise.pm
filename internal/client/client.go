// Package client porte le dialogue HTTP du poste client avec une instance
// ardoise : interrogation de la politique, dépôt et récupération en mode
// aveugle. Le chiffrement et le déchiffrement restent l'affaire de
// l'appelant (internal/cli via internal/crypto) : ce paquet ne transporte
// que du chiffré et ne voit jamais ni clair, ni clé, ni mot de passe.
package client

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ardoise.pm/internal/config"
)

// tailleMaxReponse borne la lecture de toute réponse de l'instance :
// contenu maximal admis par le produit, gonflé par base64 et l'enveloppe.
const tailleMaxReponse = 8 << 20

// ErreurAPI est une réponse d'erreur de l'instance ({"erreur":{...}}),
// porteuse du statut HTTP à traduire en code de retour (docs/man.md).
type ErreurAPI struct {
	Statut  int
	Code    string
	Message string
}

func (e *ErreurAPI) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("réponse inattendue de l'instance (HTTP %d)", e.Statut)
}

// ErreurReseau signale une instance injoignable (code de retour 9).
type ErreurReseau struct{ Cause error }

func (e *ErreurReseau) Error() string { return "instance injoignable : " + e.Cause.Error() }
func (e *ErreurReseau) Unwrap() error { return e.Cause }

// ErreurCertificatClient signale que l'instance a refusé la poignée de main
// TLS faute de certificat client acceptable : authentification refusée
// (code de retour 6), pas une défaillance réseau.
type ErreurCertificatClient struct{ Cause error }

func (e *ErreurCertificatClient) Error() string {
	return "certificat client requis ou refusé par l'instance : fournissez un certificat reconnu par son AC via « --certificat » et « --cle » (ou ARDOISE_CERTIFICAT et ARDOISE_CLE, ou la configuration client)"
}
func (e *ErreurCertificatClient) Unwrap() error { return e.Cause }

// EstRefusCertificatClient reconnaît, dans une erreur de transport, le refus
// TLS d'une instance exigeant un certificat client (alertes
// « certificate required » et « bad certificate », RFC 8446 §4.4.2.4).
func EstRefusCertificatClient(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "certificate required") ||
		strings.Contains(message, "bad certificate") ||
		strings.Contains(message, "unknown certificate authority")
}

// Client dialogue avec une instance. Il se construit avec Nouveau.
type Client struct {
	endpoint string
	http     *http.Client

	// jeton (AUTH-3) est envoyé en « Authorization: Bearer … ». Il ne
	// figure jamais dans un message d'erreur ni une sortie.
	jeton []byte

	// utilisateur et hote sont l'identité déclarée du poste (AUTH-4),
	// envoyée en en-têtes X-Ardoise-* uniquement si la politique de
	// l'instance retient l'identification déclarative.
	utilisateur, hote string

	// politique mémorise GET /v1/politique : une seule interrogation par
	// exécution, la configuration d'une instance étant figée (ADR-002).
	mu        sync.Mutex
	politique *config.Politique
}

// DefinirJeton fournit le jeton d'identité (AUTH-3), lu par l'appelant
// depuis son fichier — jamais depuis un argument de ligne de commande.
//
// Cette méthode n'est pas protégée par un mutex : elle doit être appelée
// avant toute utilisation concurrente du Client (phase d'initialisation
// mono-goroutine). Une fois le Client utilisé (Politique, Deposer ou
// Recuperer appelés), les champs d'identité sont considérés immuables.
func (c *Client) DefinirJeton(jeton []byte) { c.jeton = jeton }

// EffacerJeton met à zéro le jeton conservé dans le Client. La copie
// immuable transmise dans l'en-tête HTTP (string) subsiste jusqu'au
// ramasse-miettes — limitation documentée du runtime Go (docs/dat.md
// A.3-2, PR-006). Appeler après la dernière requête authentifiée si le
// jeton doit être effacé avant la fin du processus.
func (c *Client) EffacerJeton() {
	for i := range c.jeton {
		c.jeton[i] = 0
	}
	c.jeton = nil
}

// DeclarerIdentite fournit l'identité annoncée du poste (utilisateur et
// hôte). Elle n'est transmise que si la politique de l'instance retient
// l'identification déclarative (AUTH-4).
//
// Cette méthode n'est pas protégée par un mutex : elle doit être appelée
// avant toute utilisation concurrente du Client (phase d'initialisation
// mono-goroutine). Une fois le Client utilisé, les champs d'identité sont
// considérés immuables.
func (c *Client) DeclarerIdentite(utilisateur, hote string) {
	c.utilisateur, c.hote = utilisateur, hote
}

// Nouveau prépare un client pour l'instance donnée. La configuration TLS
// provient de l'appelant (AC interne, certificat client) ; elle ne comporte
// jamais d'InsecureSkipVerify.
func Nouveau(endpoint string, configTLS *tls.Config) *Client {
	return &Client{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		http: &http.Client{
			Timeout: 30 * time.Second,
			// Proxy volontairement absent : une instance ardoise se joint
			// en direct sur le réseau d'administration, jamais au travers
			// d'un mandataire (R10, HE-1).
			Transport: &http.Transport{TLSClientConfig: configTLS},
		},
	}
}

// Politique interroge GET /v1/politique : la configuration effective de
// l'instance, affichée avant tout envoi et opposable au client (ES-4).
// Le résultat est mémorisé pour l'exécution (ADR-002 : politique figée).
func (c *Client) Politique() (*config.Politique, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.politique != nil {
		return c.politique, nil
	}
	var politique config.Politique
	if err := c.appeler(http.MethodGet, "/v1/politique", nil, &politique); err != nil {
		return nil, err
	}
	c.politique = &politique
	return c.politique, nil
}

// entetesDeclaratifs indique si l'identité déclarée doit accompagner les
// requêtes : uniquement lorsque l'instance retient AUTH-4, ce que sa
// politique annonce (champ « identification »). Sans identité déclarée
// disponible, rien n'est envoyé — l'instance répondra 401 (code 6).
func (c *Client) entetesDeclaratifs() (bool, error) {
	if c.utilisateur == "" && c.hote == "" {
		return false, nil
	}
	politique, err := c.Politique()
	if err != nil {
		return false, err
	}
	return politique.Identification == config.MecanismeDeclaratif, nil
}

// Depot est la matière d'un dépôt : le contenu et les options de cycle de
// vie. En mode aveugle, Contenu est le chiffré client, opaque pour
// l'instance ; en mode analysé (CHIF-4), c'est le CLAIR — l'instance
// l'analyse puis le chiffre elle-même (ADR-004), et l'appelant (cmdPush) a
// affiché l'avertissement correspondant avant l'envoi.
type Depot struct {
	Contenu            []byte
	Duree              string // vide : durée par défaut de l'instance
	LectureUnique      bool
	MarquageComplement string
	// Pour restreint la lecture aux identités désignées (« --pour ») :
	// identités individuelles ou groupes « @… », vérifiés par l'instance.
	Pour []string
}

// ReponseDepot est la réponse de l'instance à un dépôt. Cle n'est présente
// qu'en mode analysé : la clé CHIF-4 générée par le serveur (base64url
// brut), remise une seule fois — l'appelant en fait le fragment
// d'identifiant puis l'efface.
type ReponseDepot struct {
	ID        string `json:"id"`
	Empreinte string `json:"empreinte"`
	Echeance  string `json:"echeance"`
	Cle       string `json:"cle"`
}

// Deposer envoie POST /v1/ardoises. En mode aveugle, seul le chiffré part
// vers l'instance : le matériel de clé reste dans l'identifiant, côté poste.
func (c *Client) Deposer(d *Depot) (*ReponseDepot, error) {
	corps := struct {
		Contenu            string   `json:"contenu"`
		Duree              string   `json:"duree,omitempty"`
		LectureUnique      bool     `json:"lecture_unique,omitempty"`
		Pour               []string `json:"pour,omitempty"`
		MarquageComplement string   `json:"marquage_complement,omitempty"`
	}{
		Contenu:            base64.StdEncoding.EncodeToString(d.Contenu),
		Duree:              d.Duree,
		LectureUnique:      d.LectureUnique,
		Pour:               d.Pour,
		MarquageComplement: d.MarquageComplement,
	}
	var reponse ReponseDepot
	if err := c.appelerAuthentifie(http.MethodPost, "/v1/ardoises", corps, &reponse); err != nil {
		return nil, err
	}
	return &reponse, nil
}

// Marquage restitue les champs de marquage servis par l'instance.
type Marquage struct {
	Actif      bool   `json:"actif"`
	Libelle    string `json:"libelle"`
	Complement string `json:"complement"`
}

// ReponseArdoise est une ardoise récupérée : toujours du chiffré.
type ReponseArdoise struct {
	Chiffre       []byte
	Empreinte     string
	Echeance      string
	LectureUnique bool
	Marquage      Marquage
}

// Recuperer appelle GET /v1/ardoises/{id}. Seul l'identifiant serveur est
// transmis : jamais le fragment de clé.
func (c *Client) Recuperer(id string) (*ReponseArdoise, error) {
	var brute struct {
		Contenu       string   `json:"contenu"`
		Empreinte     string   `json:"empreinte"`
		Echeance      string   `json:"echeance"`
		LectureUnique bool     `json:"lecture_unique"`
		Marquage      Marquage `json:"marquage"`
	}
	if err := c.appelerAuthentifie(http.MethodGet, "/v1/ardoises/"+id, nil, &brute); err != nil {
		return nil, err
	}
	chiffre, err := base64.StdEncoding.DecodeString(brute.Contenu)
	if err != nil {
		return nil, fmt.Errorf("contenu illisible dans la réponse de l'instance : %v", err)
	}
	return &ReponseArdoise{
		Chiffre:       chiffre,
		Empreinte:     brute.Empreinte,
		Echeance:      brute.Echeance,
		LectureUnique: brute.LectureUnique,
		Marquage:      brute.Marquage,
	}, nil
}

// appelerAuthentifie exécute une requête portant le matériel
// d'identification : le jeton (AUTH-3) s'il est fourni, et les en-têtes
// déclaratifs (AUTH-4) si la politique de l'instance les attend — ce qui
// suppose de la connaître, d'où l'interrogation préalable (mémorisée) de
// GET /v1/politique. Le certificat client (AUTH-1/2) est porté par la
// configuration TLS, en dessous de cette couche.
func (c *Client) appelerAuthentifie(methode, chemin string, corps any, cible any) error {
	declaratif, err := c.entetesDeclaratifs()
	if err != nil {
		return err
	}
	return c.executer(methode, chemin, corps, cible, declaratif)
}

// appeler exécute une requête JSON et décode la réponse. Toute réponse non
// 2xx devient une ErreurAPI ; toute défaillance de transport une
// ErreurReseau.
func (c *Client) appeler(methode, chemin string, corps any, cible any) error {
	return c.executer(methode, chemin, corps, cible, false)
}

func (c *Client) executer(methode, chemin string, corps any, cible any, declaratif bool) error {
	var lecteur io.Reader
	if corps != nil {
		donnees, err := json.Marshal(corps)
		if err != nil {
			return fmt.Errorf("préparation de la requête : %v", err)
		}
		lecteur = bytes.NewReader(donnees)
	}
	requete, err := http.NewRequest(methode, c.endpoint+chemin, lecteur)
	if err != nil {
		return fmt.Errorf("préparation de la requête : %v", err)
	}
	if corps != nil {
		requete.Header.Set("Content-Type", "application/json")
	}
	if c.jeton != nil {
		// AUTH-3 : le jeton part vers l'instance et nulle part ailleurs ;
		// il n'apparaît dans aucune erreur ni sortie.
		//
		// Limitation documentée (docs/dat.md A.3-2) : net/http.Header.Set
		// n'accepte que des string ; la conversion []byte → string crée
		// une copie immuable qui ne peut pas être effacée avant le
		// ramasse-miettes. L'effacement différé par crypto.Effacer() sur le
		// []byte source ne porte donc pas sur cette copie. Cette limitation
		// du runtime Go est assumée et documentée.
		requete.Header.Set("Authorization", "Bearer "+string(c.jeton))
	}
	if declaratif {
		requete.Header.Set("X-Ardoise-Utilisateur", c.utilisateur)
		requete.Header.Set("X-Ardoise-Hote", c.hote)
	}
	reponse, err := c.http.Do(requete)
	if err != nil {
		if EstRefusCertificatClient(err) {
			return &ErreurCertificatClient{Cause: err}
		}
		return &ErreurReseau{Cause: err}
	}
	defer reponse.Body.Close()
	donnees, err := io.ReadAll(io.LimitReader(reponse.Body, tailleMaxReponse))
	if err != nil {
		return &ErreurReseau{Cause: err}
	}
	if reponse.StatusCode < 200 || reponse.StatusCode > 299 {
		return erreurDepuisReponse(reponse.StatusCode, donnees)
	}
	if err := json.Unmarshal(donnees, cible); err != nil {
		return fmt.Errorf("réponse illisible de l'instance : %v", err)
	}
	return nil
}

func erreurDepuisReponse(statut int, donnees []byte) *ErreurAPI {
	var enveloppe struct {
		Erreur struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"erreur"`
	}
	e := &ErreurAPI{Statut: statut}
	if json.Unmarshal(donnees, &enveloppe) == nil {
		e.Code = enveloppe.Erreur.Code
		e.Message = enveloppe.Erreur.Message
	}
	return e
}
