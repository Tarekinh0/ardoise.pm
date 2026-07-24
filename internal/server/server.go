// Package server porte le service HTTP de l'instance ardoise : écoute TLS
// obligatoire (TLS-2 nominal, TLS-3 en repli), authentification de chaque
// opération selon le mécanisme de l'instance (AUTH-1..4, ADR-009),
// exposition de la politique effective, dépôt et récupération en mode
// aveugle adossés au magasin (mémoire ou disque chiffré), arrêt propre.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/store"
)

// periodeBalayage est la période du balayage d'expiration du magasin.
// L'expiration paresseuse à la lecture garantit qu'aucune ardoise expirée
// n'est servie entre deux passages (ADR-003).
const periodeBalayage = time.Minute

// SuitesTLS12 est la liste fermée des suites autorisées lorsque TLS 1.2 est
// admis (TLS-3) : ECDHE avec AES-GCM ou ChaCha20-Poly1305 exclusivement,
// conformément au guide TLS de l'ANSSI. TLS 1.3 impose ses propres suites.
func SuitesTLS12() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// Serveur est une instance ardoise prête à écouter.
type Serveur struct {
	adresse     string
	serveurHTTP *http.Server
	ecouteur    net.Listener
	magasin     store.Magasin
}

// Nouveau prépare le serveur : adresse d'écoute (surcharge « --ecoute »
// prioritaire sur instance.ecoute), matériel TLS et magasin selon
// retention.support. Le démarrage sans certificat et clé est refusé :
// aucun mode non chiffré n'existe (ES-5).
func Nouveau(inst *config.Instance, ecouteSurcharge string) (*Serveur, error) {
	adresse := ecouteSurcharge
	if adresse == "" {
		adresse = inst.Ecoute
	}
	if adresse == "" {
		return nil, errors.New("aucune adresse d'écoute : renseignez instance.ecoute ou l'option « --ecoute »")
	}
	if inst.Transport.Certificat == "" || inst.Transport.Cle == "" {
		return nil, errors.New("matériel TLS manquant (transport.certificat, transport.cle) : le serveur refuse de démarrer sans TLS")
	}
	// Le matériel TLS est chargé une fois, au démarrage : aucun rechargement
	// à chaud n'est prévu — le renouvellement du certificat de l'instance
	// passe par un redémarrage du service (limitation d'exploitation
	// assumée : la configuration d'une instance est figée, ADR-002).
	certificat, err := tls.LoadX509KeyPair(inst.Transport.Certificat, inst.Transport.Cle)
	if err != nil {
		return nil, fmt.Errorf("chargement du matériel TLS : %w", err)
	}
	configTLS := &tls.Config{
		Certificates: []tls.Certificate{certificat},
		MinVersion:   tls.VersionTLS13,
	}
	if inst.Transport.VersionMin == "1.2" {
		// TLS-3 : le repli 1.2 restreint les suites à la liste ANSSI ;
		// en 1.3 (défaut), les suites sont celles, fixes, du protocole.
		configTLS.MinVersion = tls.VersionTLS12
		configTLS.CipherSuites = SuitesTLS12()
	}
	if inst.Auth.ExigeCertificatClient() {
		// AUTH-1/AUTH-2 : le certificat client est exigé et vérifié dès la
		// poignée de main, exclusivement contre l'AC de auth.ac_clients —
		// jamais contre le magasin système. La période de validité est
		// contrôlée par crypto/x509 lors de la vérification de chaîne.
		acClients, err := chargerACClients(inst.Auth.ACClients)
		if err != nil {
			return nil, err
		}
		configTLS.ClientAuth = tls.RequireAndVerifyClientCert
		configTLS.ClientCAs = acClients
	}
	var jetons *Jetons
	if inst.Auth.Mecanisme == config.MecanismeJeton {
		// AUTH-3 : la table des jetons est chargée au démarrage ; illisible
		// ou trop permissive, elle empêche le démarrage.
		if jetons, err = ChargerJetons(inst.Auth.Jetons); err != nil {
			return nil, err
		}
	}
	magasin, err := nouveauMagasin(inst)
	if err != nil {
		return nil, err
	}
	return &Serveur{
		adresse: adresse,
		magasin: magasin,
		serveurHTTP: &http.Server{
			Handler:           Handler(inst, magasin, jetons),
			TLSConfig:         configTLS,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		},
	}, nil
}

// chargerACClients construit le magasin des AC habilitées à émettre les
// certificats clients (auth.ac_clients).
func chargerACClients(chemin string) (*x509.CertPool, error) {
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("AC des certificats clients : %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(donnees) {
		return nil, fmt.Errorf("AC des certificats clients %s : aucun certificat PEM exploitable", chemin)
	}
	return pool, nil
}

// nouveauMagasin monte le magasin déclaré par retention.support : mémoire
// vive (RET-1/RET-2) ou disque chiffré (RET-3, clé lue depuis
// retention.cle_magasin puis effacée localement).
func nouveauMagasin(inst *config.Instance) (store.Magasin, error) {
	switch inst.Retention.Support {
	case "disque-chiffre":
		cle, err := store.ChargerCleMagasin(inst.Retention.CleMagasin)
		if err != nil {
			return nil, err
		}
		defer crypto.Effacer(cle)
		magasin, err := store.NouveauDisque(context.Background(), inst.Retention.Repertoire, cle, periodeBalayage)
		if err != nil {
			return nil, fmt.Errorf("magasin sur disque chiffré : %w", err)
		}
		return magasin, nil
	default:
		return store.NouveauMemoire(context.Background(), periodeBalayage), nil
	}
}

// Ecouter ouvre la socket d'écoute. Séparé de Servir afin que l'appelant
// puisse connaître l'adresse effective (port choisi par le système).
func (s *Serveur) Ecouter() error {
	ecouteur, err := net.Listen("tcp", s.adresse)
	if err != nil {
		return fmt.Errorf("écoute sur %s : %w", s.adresse, err)
	}
	s.ecouteur = ecouteur
	return nil
}

// Adresse retourne l'adresse effective d'écoute.
func (s *Serveur) Adresse() string {
	if s.ecouteur != nil {
		return s.ecouteur.Addr().String()
	}
	return s.adresse
}

// Servir sert en TLS jusqu'à l'annulation du contexte (SIGINT/SIGTERM côté
// appelant), puis s'arrête proprement en laissant les échanges en cours se
// terminer, dans une limite de cinq secondes. À l'arrêt, le magasin est
// fermé : balayage stoppé, clé de magasin effacée.
func (s *Serveur) Servir(ctx context.Context) error {
	defer s.magasin.Fermer()
	if s.ecouteur == nil {
		if err := s.Ecouter(); err != nil {
			return err
		}
	}
	erreurs := make(chan error, 1)
	go func() {
		erreurs <- s.serveurHTTP.ServeTLS(s.ecouteur, "", "")
	}()
	select {
	case err := <-erreurs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		ctxArret, annuler := context.WithTimeout(context.Background(), 5*time.Second)
		defer annuler()
		errArret := s.serveurHTTP.Shutdown(ctxArret)
		if err := <-erreurs; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return errArret
	}
}
