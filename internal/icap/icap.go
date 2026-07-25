// Package icap met en œuvre le client ICAP (RFC 3507) du mode analysé :
// chaque contenu déposé est soumis en REQMOD à la chaîne d'analyse de
// l'entité, et le verdict conditionne la mise à disposition (docs/dat.md
// ADR-004, ADR-011, ANA-1/ANA-2).
//
// # Comportement fail-closed (ADR-011, non désactivable)
//
// Le produit ne rend jamais un contenu disponible sans verdict favorable :
// dépassement du délai, connexion impossible, réponse malformée, statut
// d'erreur ou verdict défavorable — tout aboutit au refus du dépôt. La
// soumission est UNIQUE : aucune tentative de réémission n'est faite, un
// second essai n'apporterait qu'un allongement de la fenêtre en clair
// (A.3-1) sans garantie supplémentaire — la réémission relève de
// l'utilisateur, qui rejoue son dépôt.
//
// # Correspondance des verdicts (RFC 3507)
//
//   - 204 (No Content) : contenu accepté sans modification — favorable ;
//   - 200 dont la section encapsulée restitue le corps INCHANGÉ : favorable
//     (serveurs ICAP n'honorant pas « Allow: 204 ») ;
//   - 200 dont la section encapsulée porte une réponse HTTP (res-hdr) ou un
//     corps modifié : le service a bloqué ou réécrit le contenu —
//     défavorable ;
//   - tout autre statut ICAP bien formé (4xx, 5xx…) : défavorable ;
//   - réponse malformée, délai dépassé, connexion impossible : indisponible.
//
// Défavorable et indisponible aboutissent tous deux au refus (fail-closed) ;
// la distinction n'alimente que le code d'erreur retourné au client
// (« analyse_defavorable » ou « analyse_indisponible », code de retour 7).
//
// # Simplifications assumées de cette version
//
//   - Pas de mode « Preview » (RFC 3507 §4.5) : le corps est transmis en
//     entier. Les contenus étant bornés par contenu.taille_max (ES-10),
//     l'économie du Preview est négligeable devant sa complexité.
//   - analyse.icap_regles est transmis dans l'en-tête
//     « X-Ardoise-Regles » de la requête ICAP : jeu de règles opaque pour le
//     produit, interprété par la chaîne d'analyse de l'entité (ANA-1). Les
//     caractères \r et \n sont rejetés (DPO-B-003, fail-closed).
//
// Aucun contenu, extrait de contenu ou clé ne figure jamais dans une erreur
// ou un message de ce paquet : seul le verdict sort.
package icap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Verdict est l'issue d'une soumission à la chaîne d'analyse.
type Verdict int

const (
	// VerdictFavorable : le contenu peut être mis à disposition.
	VerdictFavorable Verdict = iota
	// VerdictDefavorable : la chaîne d'analyse a refusé ou modifié le
	// contenu ; le dépôt est refusé (analyse_defavorable).
	VerdictDefavorable
	// VerdictIndisponible : aucun verdict n'a pu être obtenu (délai,
	// connexion, protocole) ; le dépôt est refusé (analyse_indisponible,
	// fail-closed, ADR-011).
	VerdictIndisponible
)

// Analyseur soumet un contenu et retourne le verdict. Les mises en œuvre ne
// doivent jamais conserver ni journaliser le contenu.
type Analyseur interface {
	Analyser(contenu []byte) Verdict
}

// PortICAPDefaut est le port ICAP par défaut (RFC 3507 §4.2).
const PortICAPDefaut = "1344"

// tailleMaxReponseICAP borne la lecture de la réponse ICAP : les sections
// encapsulées d'un REQMOD ne dépassent jamais le contenu soumis, lui-même
// borné par contenu.taille_max.
const tailleMaxReponseICAP = 8 << 20

// Client est le client ICAP REQMOD de l'instance. Il se construit avec
// NouveauClient et n'est adossé qu'à la bibliothèque standard (net).
type Client struct {
	adresse string // hôte:port de la connexion TCP
	uri     string // URI ICAP complète, ligne de requête REQMOD
	hote    string // en-tête Host
	delai   time.Duration
	regles  string // analyse.icap_regles, en-tête X-Ardoise-Regles
}

// NouveauClient prépare le client pour l'adresse analyse.icap_url
// (« icap://hôte:port/service », port 1344 par défaut), avec le délai
// analyse.icap_delai comme échéance TOTALE de la soumission (connexion,
// émission et lecture comprises) et analyse.icap_regles en en-tête opaque.
func NouveauClient(icapURL string, delai time.Duration, regles string) (*Client, error) {
	u, err := url.Parse(icapURL)
	if err != nil || u.Scheme != "icap" || u.Host == "" {
		return nil, fmt.Errorf("adresse ICAP « %s » invalide (attendu : icap://hôte:port/service)", icapURL)
	}
	adresse := u.Host
	if u.Port() == "" {
		adresse = net.JoinHostPort(u.Hostname(), PortICAPDefaut)
	}
	if delai <= 0 {
		return nil, errors.New("délai ICAP invalide : une échéance strictement positive est requise (fail-closed, ADR-011)")
	}
	return &Client{
		adresse: adresse,
		uri:     icapURL,
		hote:    u.Host,
		delai:   delai,
		regles:  regles,
	}, nil
}

// Analyser soumet le contenu en REQMOD et retourne le verdict. Une seule
// tentative, échéance stricte, fail-closed : toute anomalie vaut
// VerdictIndisponible (voir le commentaire de paquet).
func (c *Client) Analyser(contenu []byte) Verdict {
	echeance := time.Now().Add(c.delai)
	conn, err := net.DialTimeout("tcp", c.adresse, c.delai)
	if err != nil {
		return VerdictIndisponible
	}
	defer conn.Close()
	// Échéance dure sur l'ensemble de l'échange : la fenêtre en clair du
	// mode analysé est bornée par ce délai (A.3-1).
	if err := conn.SetDeadline(echeance); err != nil {
		conn.Close() // fermeture explicite avant retour (PR-004)
		return VerdictIndisponible
	}
	if err := c.emettreREQMOD(conn, contenu); err != nil {
		return VerdictIndisponible
	}
	return lireVerdict(bufio.NewReader(io.LimitReader(conn, tailleMaxReponseICAP)), contenu)
}

// emettreREQMOD écrit la requête ICAP : en-têtes ICAP, requête HTTP
// encapsulée (req-hdr) puis corps en transfert par tronçons (req-body,
// RFC 3507 §4.5 : le corps encapsulé est toujours en chunked).
func (c *Client) emettreREQMOD(conn net.Conn, contenu []byte) error {
	// Requête HTTP encapsulée : elle représente le dépôt à analyser. Le
	// chemin est symbolique — seule la charge compte pour l'analyse.
	var reqHTTP bytes.Buffer
	fmt.Fprintf(&reqHTTP, "POST /ardoise HTTP/1.1\r\n")
	fmt.Fprintf(&reqHTTP, "Host: %s\r\n", c.hote)
	fmt.Fprintf(&reqHTTP, "Content-Length: %d\r\n", len(contenu))
	fmt.Fprintf(&reqHTTP, "\r\n")

	var b bytes.Buffer
	fmt.Fprintf(&b, "REQMOD %s ICAP/1.0\r\n", c.uri)
	fmt.Fprintf(&b, "Host: %s\r\n", c.hote)
	fmt.Fprintf(&b, "Allow: 204\r\n")
	if c.regles != "" {
		// DPO-B-003 : les caractères \r et \n dans icap_regles doivent
		// provoquer le rejet, pas une transformation silencieuse. La
		// validation primaire a lieu au chargement de la configuration
		// (internal/config/instance.go) ; un \r ou \n résiduel est la
		// trace d'un défaut de validation — fail-closed (ADR-011).
		if strings.ContainsAny(c.regles, "\r\n") {
			return fmt.Errorf("icap_regles contient des caractères de contrôle CR/LF interdits (DPO-B-003)")
		}
		fmt.Fprintf(&b, "X-Ardoise-Regles: %s\r\n", c.regles)
	}
	fmt.Fprintf(&b, "Encapsulated: req-hdr=0, req-body=%d\r\n", reqHTTP.Len())
	fmt.Fprintf(&b, "\r\n")
	b.Write(reqHTTP.Bytes())
	fmt.Fprintf(&b, "%x\r\n", len(contenu))
	b.Write(contenu)
	fmt.Fprintf(&b, "\r\n0\r\n\r\n")

	_, err := conn.Write(b.Bytes())
	// Le tampon d'assemblage contient une copie du clair : il est effacé
	// avant de rendre la main (fenêtre en clair bornée, A.3-1).
	octets := b.Bytes()
	for i := range octets {
		octets[i] = 0
	}
	return err
}

// lireVerdict lit la réponse ICAP et la traduit selon la correspondance du
// commentaire de paquet.
func lireVerdict(r *bufio.Reader, contenu []byte) Verdict {
	statut, ok := lireLigneStatut(r)
	if !ok {
		return VerdictIndisponible
	}
	entetes, ok := lireEntetes(r)
	if !ok {
		return VerdictIndisponible
	}
	switch statut {
	case 204:
		return VerdictFavorable
	case 200:
		return verdictDepuis200(r, entetes["encapsulated"], contenu)
	default:
		// Statut ICAP bien formé mais ni 204 ni 200 : la chaîne d'analyse
		// s'est prononcée autrement qu'en faveur — défavorable.
		return VerdictDefavorable
	}
}

// verdictDepuis200 tranche une réponse 200 : réponse HTTP encapsulée
// (res-hdr/res-body) = blocage ; corps de requête restitué à l'identique =
// favorable ; corps modifié ou absent = défavorable ; malformé =
// indisponible.
func verdictDepuis200(r *bufio.Reader, encapsulated string, contenu []byte) Verdict {
	if encapsulated == "" {
		return VerdictIndisponible
	}
	sections := analyserEncapsulated(encapsulated)
	if _, blocage := sections["res-hdr"]; blocage {
		return VerdictDefavorable
	}
	if _, blocage := sections["res-body"]; blocage {
		return VerdictDefavorable
	}
	if _, avecCorps := sections["req-body"]; !avecCorps {
		// Corps supprimé (null-body) : le contenu n'est pas restitué tel
		// quel — défavorable.
		return VerdictDefavorable
	}
	if _, avecEntetes := sections["req-hdr"]; avecEntetes {
		// La section req-hdr (ligne de requête HTTP puis en-têtes) précède
		// req-body : elle est consommée sans interprétation, seule
		// l'identité du corps fait le verdict.
		if !sauterSection(r) {
			return VerdictIndisponible
		}
	}
	corps, err := io.ReadAll(io.LimitReader(httputil.NewChunkedReader(r), int64(len(contenu))+1))
	if err != nil {
		return VerdictIndisponible
	}
	if bytes.Equal(corps, contenu) {
		return VerdictFavorable
	}
	return VerdictDefavorable
}

// lireLigneStatut lit et analyse « ICAP/1.0 NNN … ».
func lireLigneStatut(r *bufio.Reader) (int, bool) {
	ligne, err := r.ReadString('\n')
	if err != nil {
		return 0, false
	}
	champs := strings.SplitN(strings.TrimRight(ligne, "\r\n"), " ", 3)
	if len(champs) < 2 || !strings.HasPrefix(champs[0], "ICAP/1.") {
		return 0, false
	}
	statut, err := strconv.Atoi(champs[1])
	if err != nil || statut < 100 || statut > 599 {
		return 0, false
	}
	return statut, true
}

// lireEntetes lit un bloc d'en-têtes jusqu'à la ligne vide, clés en
// minuscules.
func lireEntetes(r *bufio.Reader) (map[string]string, bool) {
	entetes := make(map[string]string)
	for {
		ligne, err := r.ReadString('\n')
		if err != nil {
			return nil, false
		}
		ligne = strings.TrimRight(ligne, "\r\n")
		if ligne == "" {
			return entetes, true
		}
		nom, valeur, ok := strings.Cut(ligne, ":")
		if !ok {
			return nil, false
		}
		entetes[strings.ToLower(strings.TrimSpace(nom))] = strings.TrimSpace(valeur)
	}
}

// sauterSection consomme des lignes jusqu'à la ligne vide incluse, sans les
// interpréter (section encapsulée req-hdr).
func sauterSection(r *bufio.Reader) bool {
	for {
		ligne, err := r.ReadString('\n')
		if err != nil {
			return false
		}
		if strings.TrimRight(ligne, "\r\n") == "" {
			return true
		}
	}
}

// analyserEncapsulated décompose « req-hdr=0, req-body=137 » en table
// section → position.
func analyserEncapsulated(valeur string) map[string]int {
	sections := make(map[string]int)
	for _, partie := range strings.Split(valeur, ",") {
		nom, position, ok := strings.Cut(strings.TrimSpace(partie), "=")
		if !ok {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(position)); err == nil {
			sections[strings.ToLower(strings.TrimSpace(nom))] = n
		}
	}
	return sections
}
