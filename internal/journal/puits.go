package journal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"
)

// puitsFichier est le journal local JOURN-3 : un fichier en ajout seul,
// droits 0600, une entrée JSON par ligne. La collecte périodique du fichier
// relève de l'entité (docs/dat.md §5.6 : imputabilité affaiblie, le journal
// est exposé à l'administrateur de l'instance).
type puitsFichier struct {
	fichier *os.File
}

func nouveauPuitsFichier(chemin string) (*puitsFichier, error) {
	if chemin == "" {
		return nil, fmt.Errorf("journal.fichier requis avec la destination « fichier » (JOURN-3)")
	}
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("journal local : %w", err)
	}
	// Un fichier préexistant trop permissif est resserré : le journal
	// n'appartient qu'à l'exploitant de l'instance.
	if infos, err := f.Stat(); err == nil && infos.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, fmt.Errorf("journal local : droits : %w", err)
		}
	}
	return &puitsFichier{fichier: f}, nil
}

func (p *puitsFichier) emettre(_ *Entree, canonique []byte) error {
	ligne := make([]byte, 0, len(canonique)+1)
	ligne = append(ligne, canonique...)
	ligne = append(ligne, '\n')
	if _, err := p.fichier.Write(ligne); err != nil {
		return fmt.Errorf("journal local : %w", err)
	}
	return nil
}

func (p *puitsFichier) fermer() error {
	if err := p.fichier.Sync(); err != nil {
		p.fichier.Close()
		return err
	}
	return p.fichier.Close()
}

// puitsSyslogTLS est l'émetteur JOURN-1/JOURN-2 : messages syslog RFC 5424
// vers la zone de journalisation dédiée, transport TLS avec tramage par
// comptage d'octets (RFC 5425 : « LEN SP MSG »). L'autorité de
// certification du collecteur provient de journal.ac (PEM), à défaut du
// magasin système. Jamais d'InsecureSkipVerify.
//
// La connexion s'établit paresseusement, à la première émission, et se
// rétablit à l'émission suivante après une défaillance — une seule
// tentative par entrée : l'émission étant asynchrone et non bloquante, un
// collecteur indisponible se traduit par des échecs comptés, jamais par un
// blocage du service.
type puitsSyslogTLS struct {
	adresse   string
	instance  string
	configTLS *tls.Config

	mu   sync.Mutex
	conn net.Conn
}

// delaiSyslog borne l'établissement de connexion et chaque écriture vers le
// collecteur : la goroutine d'émission ne reste jamais suspendue sans borne.
const delaiSyslog = 10 * time.Second

func nouveauPuitsSyslogTLS(destination, cheminAC, instance string) (*puitsSyslogTLS, error) {
	u, err := url.Parse(destination)
	if err != nil || u.Scheme != "syslog+tls" || u.Host == "" || u.Port() == "" {
		return nil, fmt.Errorf("journal.destination « %s » invalide (attendu : syslog+tls://hôte:port)", destination)
	}
	configTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: u.Hostname(),
	}
	if cheminAC != "" {
		donnees, err := os.ReadFile(cheminAC)
		if err != nil {
			return nil, fmt.Errorf("journal.ac : %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(donnees) {
			return nil, fmt.Errorf("journal.ac %s : aucun certificat PEM exploitable", cheminAC)
		}
		configTLS.RootCAs = pool
	}
	return &puitsSyslogTLS{
		adresse:   u.Host,
		instance:  instance,
		configTLS: configTLS,
	}, nil
}

// prioriteSyslog est le PRI RFC 5424 des entrées : facilité 13 (journal
// d'audit), sévérité 6 (informationnel) — 13×8+6 = 110.
const prioriteSyslog = 110

func (p *puitsSyslogTLS) emettre(e *Entree, canonique []byte) error {
	// Message RFC 5424 : HOSTNAME porte le nom d'instance (la zone d'où
	// provient l'entrée), APP-NAME le produit, MSGID l'événement. Le corps
	// est l'entrée JSON canonique — celle-là même que couvre le chaînage.
	message := fmt.Sprintf("<%d>1 %s %s ardoise - %s - %s",
		prioriteSyslog, e.Horodatage, p.instance, e.Evenement, canonique)
	trame := fmt.Sprintf("%d %s", len(message), message)

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: delaiSyslog}, "tcp", p.adresse, p.configTLS)
		if err != nil {
			return fmt.Errorf("collecteur injoignable : %w", err)
		}
		p.conn = conn
	}
	p.conn.SetWriteDeadline(time.Now().Add(delaiSyslog))
	if _, err := p.conn.Write([]byte(trame)); err != nil {
		// La connexion est abandonnée ; la prochaine émission retentera.
		p.conn.Close()
		p.conn = nil
		return fmt.Errorf("émission vers le collecteur : %w", err)
	}
	return nil
}

func (p *puitsSyslogTLS) fermer() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		err := p.conn.Close()
		p.conn = nil
		return err
	}
	return nil
}
