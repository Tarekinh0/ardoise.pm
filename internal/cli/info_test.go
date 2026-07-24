package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
)

// genererMaterielTLS produit un certificat auto-signé pour 127.0.0.1 dans
// t.TempDir() (voir aussi internal/server/server_test.go).
func genererMaterielTLS(t *testing.T) (cheminCertificat, cheminCle string) {
	t.Helper()
	rep := t.TempDir()
	clePrivee, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ardoise-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, modele, &clePrivee.PublicKey, clePrivee)
	if err != nil {
		t.Fatal(err)
	}
	cleDER, err := x509.MarshalECPrivateKey(clePrivee)
	if err != nil {
		t.Fatal(err)
	}
	cheminCertificat = filepath.Join(rep, "instance.pem")
	cheminCle = filepath.Join(rep, "instance.key")
	if err := os.WriteFile(cheminCertificat, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cheminCle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cleDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cheminCertificat, cheminCle
}

// demarrerInstance démarre une vraie instance TLS sur 127.0.0.1 et retourne
// son adresse et le chemin du certificat à épingler comme AC.
func demarrerInstance(t *testing.T) (adresse, cheminAC string) {
	t.Helper()
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	// Identification déclarative : « info » n'interroge que /v1/politique,
	// servie avant authentification ; le parcours mTLS complet est couvert
	// par auth_integration_test.go.
	donnees := fmt.Sprintf(`{
		"instance":  {"nom": "ardoise-adm-zone-reseau", "mode": "aveugle", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": "declaratif"},
		"contenu":   {"chiffrement": "cle", "taille_max": "256Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"journal":   {"destination": "syslog+tls://journal.adm.interne:6514", "chainage": true},
		"transport": {"certificat": %q, "cle": %q},
		"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"}
	}`, cheminCertificat, cheminCle)
	instance, problemes, err := config.Analyser([]byte(donnees))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}
	serveur, err := server.Nouveau(instance, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := serveur.Ecouter(); err != nil {
		t.Fatal(err)
	}
	ctx, annuler := context.WithCancel(context.Background())
	termine := make(chan error, 1)
	go func() { termine <- serveur.Servir(ctx) }()
	t.Cleanup(func() {
		annuler()
		if err := <-termine; err != nil {
			t.Errorf("arrêt propre attendu : %v", err)
		}
	})
	return serveur.Adresse(), cheminCertificat
}

func TestInfoAllerRetour(t *testing.T) {
	adresse, cheminAC := demarrerInstance(t)
	r := executer(t, []string{"info", "-e", "https://" + adresse, "--ac", cheminAC})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
	for _, motif := range []string{
		"Instance",
		"ardoise-adm-zone-reseau",
		"Mode",
		"aveugle (le serveur ne peut à aucun moment lire les contenus)",
		"Identification",
		"AUTH-4",
		"24h maximum, 1h par défaut",
		"256 Kio",
		"Rémanence locale",
		"interdite",
		"DIFFUSION RESTREINTE",
	} {
		if !strings.Contains(r.stdout, motif) {
			t.Errorf("motif %q absent :\n%s", motif, r.stdout)
		}
	}
}

func TestInfoJSON(t *testing.T) {
	adresse, cheminAC := demarrerInstance(t)
	r := executer(t, []string{"info", "--json", "-e", "https://" + adresse, "--ac", cheminAC})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
	var politique config.Politique
	if err := json.Unmarshal([]byte(r.stdout), &politique); err != nil {
		t.Fatalf("JSON illisible : %v\n%s", err, r.stdout)
	}
	if politique.Instance != "ardoise-adm-zone-reseau" || len(politique.Options) != 9 {
		t.Errorf("politique inattendue : %+v", politique)
	}
}

func TestInfoEndpointDepuisEnvironnement(t *testing.T) {
	adresse, cheminAC := demarrerInstance(t)
	r := executer(t, []string{"info"}, avecEnvironnement(map[string]string{
		"ARDOISE_ENDPOINT": "https://" + adresse,
		"ARDOISE_AC":       cheminAC,
	}))
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
}

func TestInfoConfigurationClient(t *testing.T) {
	adresse, cheminAC := demarrerInstance(t)
	cheminClient := filepath.Join(t.TempDir(), "client.json")
	contenu := fmt.Sprintf(`{"endpoint":"https://%s","ac":%q}`, adresse, cheminAC)
	if err := os.WriteFile(cheminClient, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	r := executer(t, []string{"info"}, func(ctx *Contexte) {
		ctx.CheminsConfigClient = []string{cheminClient}
	})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
}

func TestInfoSansEndpoint(t *testing.T) {
	r := executer(t, []string{"info"})
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeUsage, r.stderr)
	}
	if !strings.Contains(r.stderr, "ARDOISE_ENDPOINT") {
		t.Errorf("le message doit guider l'utilisateur :\n%s", r.stderr)
	}
}

func TestInfoRefuseHTTP(t *testing.T) {
	r := executer(t, []string{"info", "-e", "http://ardoise.interne:8080"})
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d", r.code, CodeUsage)
	}
	if !strings.Contains(r.stderr, "https") {
		t.Errorf("le refus doit citer https :\n%s", r.stderr)
	}
}

func TestInfoInstanceInjoignable(t *testing.T) {
	// Port réservé puis refermé : la connexion doit échouer immédiatement.
	ecouteur, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adresse := ecouteur.Addr().String()
	ecouteur.Close()
	r := executer(t, []string{"info", "-e", "https://" + adresse})
	if r.code != CodeInjoignable {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeInjoignable, r.stderr)
	}
	if !strings.Contains(r.stderr, "injoignable") {
		t.Errorf("message attendu :\n%s", r.stderr)
	}
}

func TestInfoACIllisible(t *testing.T) {
	r := executer(t, []string{"info", "-e", "https://ardoise.interne:8443", "--ac", filepath.Join(t.TempDir(), "absent.pem")})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
}

func TestInfoCertificatSansCle(t *testing.T) {
	r := executer(t, []string{"info", "-e", "https://ardoise.interne:8443", "--certificat", "/tmp/poste.pem"})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d", r.code, CodeErreur)
	}
	if !strings.Contains(r.stderr, "vont de pair") {
		t.Errorf("message attendu :\n%s", r.stderr)
	}
}
