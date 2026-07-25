package journal

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// journalFichier monte un journal JOURN-3 vers un fichier de t.TempDir.
func journalFichier(t *testing.T, chainage bool) (*Journal, string) {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := Nouveau(Config{
		Instance:    "ardoise-test",
		Niveau:      "DIFFUSION RESTREINTE",
		Destination: "fichier",
		Chainage:    chainage,
		Fichier:     chemin,
		Stderr:      io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	return j, chemin
}

func lignesDe(t *testing.T, chemin string) [][]byte {
	t.Helper()
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	var lignes [][]byte
	for _, l := range bytes.Split(donnees, []byte("\n")) {
		if len(l) > 0 {
			lignes = append(lignes, l)
		}
	}
	return lignes
}

// TestEvenements : une entrée par événement du modèle, champs communs
// renseignés par Consigner (horodatage, instance, niveau).
func TestEvenements(t *testing.T) {
	j, chemin := journalFichier(t, false)
	evenements := []string{
		EvenementDepot, EvenementLecture, EvenementDestructionEcheance,
		EvenementDestructionLecture, EvenementDepotRefuseAnalyse, EvenementAccesRefuse,
	}
	for _, e := range evenements {
		j.Consigner(Entree{
			Evenement: e,
			Identite:  &Identite{Utilisateur: "alice.durand", Mecanisme: "certificat"},
			IDServeur: "abcdefgh2345",
			Empreinte: strings.Repeat("ab", 32),
		})
	}
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}
	lignes := lignesDe(t, chemin)
	if len(lignes) != len(evenements) {
		t.Fatalf("%d entrées émises, attendu %d", len(lignes), len(evenements))
	}
	for i, ligne := range lignes {
		var e Entree
		if err := json.Unmarshal(ligne, &e); err != nil {
			t.Fatalf("entrée %d illisible : %v", i, err)
		}
		if e.Evenement != evenements[i] {
			t.Errorf("entrée %d : evenement = %q, attendu %q", i, e.Evenement, evenements[i])
		}
		if e.Instance != "ardoise-test" || e.Niveau != "DIFFUSION RESTREINTE" {
			t.Errorf("entrée %d : instance/niveau non renseignés : %+v", i, e)
		}
		if e.Horodatage == "" {
			t.Errorf("entrée %d : horodatage vide", i)
		} else if _, err := time.Parse(time.RFC3339Nano, e.Horodatage); err != nil {
			t.Errorf("entrée %d : horodatage non RFC 3339 : %q", i, e.Horodatage)
		}
	}
}

// TestMetadonneesSeulement (ADR-005) : un aller-retour complet — contenu,
// clé, fragment, mot de passe — ne laisse RIEN de tout cela dans le
// journal, qui ne porte que des métadonnées.
func TestMetadonneesSeulement(t *testing.T) {
	j, chemin := journalFichier(t, true)
	const (
		contenu    = "extrait-tres-identifiable-du-contenu-clair"
		cle        = "Zt8mQ4vP1nKcW7yE0sJdL5hB2gT6uXaZbCdEfGhIjKl"
		motDePasse = "mot-de-passe-tres-secret"
	)
	identifiantComplet := "abcdefgh2345#" + cle
	// L'appelant respecte le contrat : il ne consigne que des métadonnées.
	// Le test vérifie que ce qui sort du journal n'expose rien des secrets
	// manipulés par ailleurs pendant l'opération.
	j.Consigner(Entree{
		Evenement: EvenementDepot,
		Identite:  &Identite{Utilisateur: "alice.durand", Mecanisme: "certificat"},
		IDServeur: "abcdefgh2345",
		Empreinte: strings.Repeat("cd", 32),
		Echeance:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	j.Consigner(Entree{
		Evenement: EvenementLecture,
		Identite:  &Identite{Utilisateur: "bob.martin", Mecanisme: "jeton"},
		IDServeur: "abcdefgh2345",
		Empreinte: strings.Repeat("cd", 32),
	})
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	for _, interdit := range []string{contenu, cle, motDePasse, identifiantComplet, "#"} {
		if bytes.Contains(donnees, []byte(interdit)) {
			t.Errorf("le journal contient %q — métadonnées seulement (ADR-005)", interdit)
		}
	}
	// L'identifiant serveur seul, lui, est bien présent (corrélation des
	// actes — voir le commentaire de paquet).
	if !bytes.Contains(donnees, []byte("abcdefgh2345")) {
		t.Error("l'identifiant serveur devrait figurer dans les entrées")
	}
}

// TestChainage : la chaîne recalculée sur les entrées émises est intègre ;
// toute altération, suppression ou réordonnance est détectée.
func TestChainage(t *testing.T) {
	j, chemin := journalFichier(t, true)
	ancrage := j.Ancrage()
	for i := 0; i < 5; i++ {
		j.Consigner(Entree{
			Evenement: EvenementDepot,
			IDServeur: fmt.Sprintf("ardoise%05d", i),
			Empreinte: strings.Repeat("ef", 32),
		})
	}
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}
	lignes := lignesDe(t, chemin)
	if len(lignes) != 5 {
		t.Fatalf("%d entrées, attendu 5", len(lignes))
	}
	for _, ligne := range lignes {
		var e Entree
		if err := json.Unmarshal(ligne, &e); err != nil {
			t.Fatal(err)
		}
		if e.Chaine == "" {
			t.Fatal("entrée sans champ chaine avec le chaînage actif (JOURN-1)")
		}
	}

	if i, err := VerifierChaine(ancrage, lignes); err != nil || i != -1 {
		t.Fatalf("chaîne intègre attendue, rupture à %d (err %v)", i, err)
	}

	// Altération d'un champ de l'entrée 2.
	alterees := make([][]byte, len(lignes))
	copy(alterees, lignes)
	alterees[2] = bytes.Replace(alterees[2], []byte("ardoise00002"), []byte("ardoise99999"), 1)
	if i, _ := VerifierChaine(ancrage, alterees); i != 2 {
		t.Fatalf("altération : rupture à %d, attendu 2", i)
	}

	// Suppression de l'entrée 1 : la rupture apparaît dès sa place.
	tronquees := append([][]byte{lignes[0]}, lignes[2:]...)
	if i, _ := VerifierChaine(ancrage, tronquees); i != 1 {
		t.Fatalf("suppression : rupture à %d, attendu 1", i)
	}

	// Réordonnance des entrées 3 et 4.
	inversees := make([][]byte, len(lignes))
	copy(inversees, lignes)
	inversees[3], inversees[4] = inversees[4], inversees[3]
	if i, _ := VerifierChaine(ancrage, inversees); i != 3 {
		t.Fatalf("réordonnance : rupture à %d, attendu 3", i)
	}

	// Mauvais ancrage (autre genèse) : rupture dès la première entrée.
	if i, _ := VerifierChaine(Genese("autre-instance", time.Now()), lignes); i != 0 {
		t.Fatalf("mauvais ancrage : rupture à %d, attendu 0", i)
	}
}

// TestFichierDroitsEtAjout : le journal local est en 0600 et les émissions
// successives (y compris après réouverture) s'ajoutent sans écraser.
func TestFichierDroitsEtAjout(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "journal.jsonl")
	config := Config{
		Instance:    "ardoise-test",
		Destination: "fichier",
		Fichier:     chemin,
		Stderr:      io.Discard,
	}
	j, err := Nouveau(config)
	if err != nil {
		t.Fatal(err)
	}
	j.Consigner(Entree{Evenement: EvenementDepot, IDServeur: "abcdefgh2345"})
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}
	infos, err := os.Stat(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if infos.Mode().Perm() != 0o600 {
		t.Fatalf("droits du journal = %v, attendu 0600", infos.Mode().Perm())
	}
	// Réouverture : ajout, jamais troncature.
	j2, err := Nouveau(config)
	if err != nil {
		t.Fatal(err)
	}
	j2.Consigner(Entree{Evenement: EvenementLecture, IDServeur: "abcdefgh2345"})
	if err := j2.Fermer(); err != nil {
		t.Fatal(err)
	}
	if lignes := lignesDe(t, chemin); len(lignes) != 2 {
		t.Fatalf("%d entrées après réouverture, attendu 2 (ajout seul)", len(lignes))
	}
}

// TestJOURN4AucuneEmission : la destination « aucun » rend un Journal nil,
// dont chaque méthode est sûre et n'émet rien nulle part.
func TestJOURN4AucuneEmission(t *testing.T) {
	j, err := Nouveau(Config{Instance: "ardoise-test", Destination: "aucun"})
	if err != nil {
		t.Fatal(err)
	}
	if j != nil {
		t.Fatal("JOURN-4 : Journal nil attendu")
	}
	// Toutes les opérations sur nil sont des non-événements.
	j.Consigner(Entree{Evenement: EvenementDepot})
	if j.Abandons() != 0 {
		t.Fatal("Abandons() != 0 sur un journal nil")
	}
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}
}

// TestValidation : les montages invalides sont refusés au démarrage.
func TestValidation(t *testing.T) {
	if _, err := Nouveau(Config{Instance: "i", Destination: "fichier"}); err == nil {
		t.Error("fichier absent : erreur attendue")
	}
	if _, err := Nouveau(Config{Instance: "i", Destination: "carrier-pigeon://x"}); err == nil {
		t.Error("destination inconnue : erreur attendue")
	}
	if _, err := Nouveau(Config{Instance: "i", Destination: "syslog+tls://collecteur.interne:6514", AC: "/inexistant.pem"}); err == nil {
		t.Error("AC illisible : erreur attendue")
	}
}

// collecteurTLS est un collecteur syslog+TLS de test : il accepte les
// connexions TLS et pousse chaque trame RFC 5425 reçue dans trames.
type collecteurTLS struct {
	ecouteur net.Listener
	cheminAC string
	trames   chan string
}

func demarrerCollecteurTLS(t *testing.T) *collecteurTLS {
	t.Helper()
	clePrivee, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "collecteur de test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, modele, &clePrivee.PublicKey, clePrivee)
	if err != nil {
		t.Fatal(err)
	}
	certificat := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: clePrivee}
	ecouteur, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificat},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	cheminAC := filepath.Join(t.TempDir(), "ac.pem")
	if err := os.WriteFile(cheminAC, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &collecteurTLS{ecouteur: ecouteur, cheminAC: cheminAC, trames: make(chan string, 64)}
	go c.servir()
	t.Cleanup(func() { ecouteur.Close() })
	return c
}

func (c *collecteurTLS) adresse() string { return c.ecouteur.Addr().String() }

func (c *collecteurTLS) servir() {
	for {
		conn, err := c.ecouteur.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			r := bufio.NewReader(conn)
			for {
				// Tramage RFC 5425 : « LEN SP MSG ».
				enTete, err := r.ReadString(' ')
				if err != nil {
					return
				}
				n, err := strconv.Atoi(strings.TrimSuffix(enTete, " "))
				if err != nil || n <= 0 || n > 1<<20 {
					return
				}
				message := make([]byte, n)
				if _, err := io.ReadFull(r, message); err != nil {
					return
				}
				c.trames <- string(message)
			}
		}()
	}
}

// TestSyslogTLS : les entrées partent vers le collecteur en messages
// RFC 5424 sous tramage RFC 5425, avec l'entrée JSON canonique en corps.
func TestSyslogTLS(t *testing.T) {
	collecteur := demarrerCollecteurTLS(t)
	j, err := Nouveau(Config{
		Instance:    "ardoise-test",
		Niveau:      "DIFFUSION RESTREINTE",
		Destination: "syslog+tls://" + collecteur.adresse(),
		Chainage:    true,
		AC:          collecteur.cheminAC,
		Stderr:      io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	ancrage := j.Ancrage()
	j.Consigner(Entree{
		Evenement: EvenementDepot,
		Identite:  &Identite{Utilisateur: "alice.durand", Mecanisme: "certificat"},
		IDServeur: "abcdefgh2345",
		Empreinte: strings.Repeat("ab", 32),
	})
	j.Consigner(Entree{Evenement: EvenementLecture, IDServeur: "abcdefgh2345"})
	if err := j.Fermer(); err != nil {
		t.Fatal(err)
	}

	var canoniques [][]byte
	for i := 0; i < 2; i++ {
		select {
		case trame := <-collecteur.trames:
			// Message RFC 5424 : <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID
			// MSGID SD MSG — le corps est l'entrée JSON.
			if !strings.HasPrefix(trame, "<110>1 ") {
				t.Fatalf("PRI/VERSION inattendus : %q", trame)
			}
			champs := strings.SplitN(trame, " ", 8)
			if len(champs) != 8 {
				t.Fatalf("message RFC 5424 incomplet : %q", trame)
			}
			if champs[2] != "ardoise-test" || champs[3] != "ardoise" {
				t.Fatalf("HOSTNAME/APP-NAME inattendus : %q", trame)
			}
			var e Entree
			if err := json.Unmarshal([]byte(champs[7]), &e); err != nil {
				t.Fatalf("corps non JSON : %v (%q)", err, champs[7])
			}
			if e.Evenement != champs[5] {
				t.Fatalf("MSGID %q != evenement %q", champs[5], e.Evenement)
			}
			canoniques = append(canoniques, []byte(champs[7]))
		case <-time.After(5 * time.Second):
			t.Fatal("trame non reçue par le collecteur")
		}
	}
	// Le chaînage couvre exactement les corps émis (JOURN-1).
	if i, err := VerifierChaine(ancrage, canoniques); err != nil || i != -1 {
		t.Fatalf("chaîne des trames : rupture à %d (err %v)", i, err)
	}
}

// TestNonBloquant : un collecteur qui accepte la connexion TLS puis ne lit
// jamais ne retarde pas Consigner — l'émission est asynchrone et la file
// abandonne les entrées les plus anciennes plutôt que de bloquer.
func TestNonBloquant(t *testing.T) {
	// Un faux collecteur : accepte les connexions TCP puis ne lit jamais —
	// même la poignée de main TLS n'aboutit pas.
	ecouteur, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ecouteur.Close()
	go func() {
		for {
			conn, err := ecouteur.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Jamais de lecture, jamais de poignée de main.
		}
	}()

	var alertes bytes.Buffer
	j, err := Nouveau(Config{
		Instance:    "ardoise-test",
		Destination: "syslog+tls://" + ecouteur.Addr().String(),
		Stderr:      &alertes,
	})
	if err != nil {
		t.Fatal(err)
	}
	depart := time.Now()
	for i := 0; i < 4*tailleFile; i++ {
		j.Consigner(Entree{Evenement: EvenementDepot, IDServeur: "abcdefgh2345"})
	}
	ecoule := time.Since(depart)
	// 1024 émissions vers un collecteur bloqué : chaque Consigner doit
	// rendre la main immédiatement (fraction de seconde pour l'ensemble).
	if ecoule > 2*time.Second {
		t.Fatalf("Consigner a bloqué : %v pour %d entrées", ecoule, 4*tailleFile)
	}
	if j.Abandons() == 0 {
		t.Error("file saturée : des abandons étaient attendus")
	}
	// Fermer n'attend que le drainage de la file bornée, dont chaque
	// émission est elle-même bornée par le délai de connexion.
	fini := make(chan error, 1)
	go func() { fini <- j.Fermer() }()
	select {
	case <-fini:
	case <-time.After(30 * time.Second):
		t.Fatal("Fermer n'a pas rendu la main")
	}
	if !strings.Contains(alertes.String(), "abandonnée") {
		t.Error("aucun avertissement d'abandon sur la sortie d'erreur")
	}
}
