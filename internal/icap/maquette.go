package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"sync"
	"time"
)

// Comportement d'une Maquette : le scénario ICAP qu'elle rejoue à chaque
// connexion.
type Comportement int

const (
	// MaquetteFavorable répond 204 (contenu accepté sans modification).
	MaquetteFavorable Comportement = iota
	// MaquetteEcho répond 200 en restituant le corps à l'identique :
	// verdict favorable pour un serveur n'honorant pas « Allow: 204 ».
	MaquetteEcho
	// MaquetteBlocage répond 200 avec une réponse HTTP encapsulée
	// (res-hdr) : le service a bloqué le contenu — défavorable.
	MaquetteBlocage
	// MaquetteModifie répond 200 avec un corps de requête réécrit :
	// défavorable.
	MaquetteModifie
	// MaquetteErreur répond un statut ICAP d'erreur (500) : défavorable.
	MaquetteErreur
	// MaquetteMuette lit la requête puis ne répond jamais : le client
	// atteint son échéance — indisponible.
	MaquetteMuette
	// MaquetteCharabia répond des octets qui ne sont pas de l'ICAP :
	// indisponible.
	MaquetteCharabia
	// MaquetteCoupure ferme la connexion sitôt la requête lue :
	// indisponible.
	MaquetteCoupure
)

// Maquette est un serveur ICAP minimal (net.Listener), parlant juste assez
// de RFC 3507 pour éprouver le client REQMOD : verdicts favorables,
// blocages, erreurs, silences et réponses malformées. Employée par les
// tests du produit et réutilisable par l'environnement d'intégration
// (docker-compose de la phase conteneur).
type Maquette struct {
	ecouteur net.Listener

	mu             sync.Mutex
	comportement   Comportement
	dernierEntetes map[string]string
	dernierCorps   []byte
}

// DemarrerMaquette écoute sur une adresse locale éphémère et sert le
// comportement demandé. L'appelant ferme avec Fermer.
func DemarrerMaquette(comportement Comportement) (*Maquette, error) {
	ecouteur, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	m := &Maquette{ecouteur: ecouteur, comportement: comportement}
	go m.servir()
	return m, nil
}

// URL retourne l'adresse ICAP de la maquette (icap://hôte:port/analyse).
func (m *Maquette) URL() string {
	return fmt.Sprintf("icap://%s/analyse", m.ecouteur.Addr().String())
}

// Fermer arrête l'écoute.
func (m *Maquette) Fermer() { m.ecouteur.Close() }

// DefinirComportement change le scénario pour les connexions suivantes.
func (m *Maquette) DefinirComportement(c Comportement) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.comportement = c
}

// DernierEntetes restitue les en-têtes ICAP de la dernière requête reçue
// (clés en minuscules) — pour vérifier, entre autres, X-Ardoise-Regles.
func (m *Maquette) DernierEntetes() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	copie := make(map[string]string, len(m.dernierEntetes))
	for k, v := range m.dernierEntetes {
		copie[k] = v
	}
	return copie
}

// DernierCorps restitue le corps encapsulé de la dernière requête reçue :
// le contenu soumis à l'analyse, tel que la maquette l'a vu.
func (m *Maquette) DernierCorps() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.dernierCorps...)
}

func (m *Maquette) servir() {
	for {
		conn, err := m.ecouteur.Accept()
		if err != nil {
			return
		}
		go m.traiter(conn)
	}
}

func (m *Maquette) traiter(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(conn)

	// Ligne de requête ICAP puis en-têtes.
	if _, err := r.ReadString('\n'); err != nil {
		return
	}
	entetes, ok := lireEntetes(r)
	if !ok {
		return
	}
	// Section encapsulée : req-hdr (sautée) puis req-body en tronçons.
	sections := analyserEncapsulated(entetes["encapsulated"])
	if _, avec := sections["req-hdr"]; avec {
		if !sauterSection(r) {
			return
		}
	}
	var corps []byte
	if _, avec := sections["req-body"]; avec {
		var err error
		corps, err = io.ReadAll(httputil.NewChunkedReader(r))
		if err != nil {
			return
		}
	}

	m.mu.Lock()
	m.dernierEntetes = entetes
	m.dernierCorps = corps
	comportement := m.comportement
	m.mu.Unlock()

	switch comportement {
	case MaquetteFavorable:
		fmt.Fprintf(conn, "ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n")
	case MaquetteEcho:
		m.repondre200(conn, corps)
	case MaquetteModifie:
		m.repondre200(conn, append([]byte("modifie: "), corps...))
	case MaquetteBlocage:
		page := "contenu refuse par la chaine d'analyse"
		var resHTTP bytes.Buffer
		fmt.Fprintf(&resHTTP, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n", len(page))
		fmt.Fprintf(conn, "ICAP/1.0 200 OK\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n", resHTTP.Len())
		conn.Write(resHTTP.Bytes())
		fmt.Fprintf(conn, "%x\r\n%s\r\n0\r\n\r\n", len(page), page)
	case MaquetteErreur:
		fmt.Fprintf(conn, "ICAP/1.0 500 Server Error\r\nEncapsulated: null-body=0\r\n\r\n")
	case MaquetteMuette:
		// Aucune réponse : le client doit atteindre son échéance. La
		// connexion reste ouverte jusqu'à ce que le client la ferme.
		io.Copy(io.Discard, r)
	case MaquetteCharabia:
		fmt.Fprintf(conn, "ceci n'est pas de l'ICAP\r\n\r\n")
	case MaquetteCoupure:
		// Fermeture immédiate (defer).
	}
}

// repondre200 restitue un corps de requête (200, req-hdr + req-body).
func (m *Maquette) repondre200(conn net.Conn, corps []byte) {
	reqHTTP := "POST /ardoise HTTP/1.1\r\nHost: maquette\r\n\r\n"
	fmt.Fprintf(conn, "ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, req-body=%d\r\n\r\n", len(reqHTTP))
	io.WriteString(conn, reqHTTP)
	fmt.Fprintf(conn, "%x\r\n", len(corps))
	conn.Write(corps)
	fmt.Fprintf(conn, "\r\n0\r\n\r\n")
}

// AnalyseurFixe est un Analyseur de test qui rend toujours le même verdict,
// sans réseau. Les tests du serveur HTTP s'en servent pour éprouver le
// pipeline du mode analysé sans maquette ICAP.
type AnalyseurFixe struct {
	Reponse Verdict

	mu      sync.Mutex
	vus     int
	dernier []byte
}

// Analyser retourne le verdict fixé et retient une copie du contenu soumis
// (tests uniquement — jamais dans le produit).
func (a *AnalyseurFixe) Analyser(contenu []byte) Verdict {
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
