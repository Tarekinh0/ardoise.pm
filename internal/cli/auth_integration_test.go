package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
)

// igcClients est une IGC jetable pour les certificats clients (AUTH-2).
type igcClients struct {
	ca       *x509.Certificate
	cleCA    *ecdsa.PrivateKey
	cheminCA string
	rep      string
}

func nouvelleIGCClients(t *testing.T) *igcClients {
	t.Helper()
	rep := t.TempDir()
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AC clients de test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, modele, &cle.PublicKey, cle)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	cheminCA := filepath.Join(rep, "ac-clients.pem")
	if err := os.WriteFile(cheminCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &igcClients{ca: ca, cleCA: cle, cheminCA: cheminCA, rep: rep}
}

// emettrePoste émet un certificat client signé par l'AC et l'écrit avec sa
// clé dans des fichiers PEM (comme le matériel d'un poste).
func (igc *igcClients) emettrePoste(t *testing.T, cn string) (cheminCertificat, cheminCle string) {
	t.Helper()
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, igc.ca, &cle.PublicKey, igc.cleCA)
	if err != nil {
		t.Fatal(err)
	}
	cleDER, err := x509.MarshalECPrivateKey(cle)
	if err != nil {
		t.Fatal(err)
	}
	cheminCertificat = filepath.Join(igc.rep, cn+".pem")
	cheminCle = filepath.Join(igc.rep, cn+".key")
	if err := os.WriteFile(cheminCertificat, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cheminCle, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cleDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cheminCertificat, cheminCle
}

// demarrerInstanceMTLS démarre une vraie instance mTLS (AUTH-2) : le
// certificat client est exigé et vérifié dès la poignée de main.
func demarrerInstanceMTLS(t *testing.T, igc *igcClients) (adresse, cheminACServeur string) {
	t.Helper()
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	donnees := fmt.Sprintf(`{
		"instance":  {"nom": "ardoise-mtls", "mode": "aveugle", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": "mtls", "ac_clients": %q},
		"contenu":   {"chiffrement": "cle", "taille_max": "64Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"transport": {"certificat": %q, "cle": %q},
		"marquage":  {"actif": false}
	}`, igc.cheminCA, cheminCertificat, cheminCle)
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

// TestIntegrationMTLS couvre AUTH-2 de bout en bout par la CLI : dépôt et
// récupération avec un certificat de la bonne AC (options puis variables
// d'environnement), refus explicite (code 6) sans certificat.
func TestIntegrationMTLS(t *testing.T) {
	igc := nouvelleIGCClients(t)
	adresse, cheminACServeur := demarrerInstanceMTLS(t, igc)
	cheminCertificat, cheminCle := igc.emettrePoste(t, "alice.durand")
	env := map[string]string{
		"ARDOISE_ENDPOINT": "https://" + adresse,
		"ARDOISE_AC":       cheminACServeur,
	}

	// Options --certificat/--cle.
	r := pousser(t, env, "secret pour la zone", []string{"--certificat", cheminCertificat, "--cle", cheminCle})
	identifiant := identifiantDe(t, r)

	// Variables ARDOISE_CERTIFICAT/ARDOISE_CLE.
	envCertificat := map[string]string{
		"ARDOISE_ENDPOINT":   env["ARDOISE_ENDPOINT"],
		"ARDOISE_AC":         cheminACServeur,
		"ARDOISE_CERTIFICAT": cheminCertificat,
		"ARDOISE_CLE":        cheminCle,
	}
	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(envCertificat))
	if lecture.code != CodeOK || lecture.stdout != "secret pour la zone" {
		t.Fatalf("get mTLS : code = %d, stdout = %q (stderr : %s)", lecture.code, lecture.stdout, lecture.stderr)
	}

	// Sans certificat : refus d'authentification (code 6), message qui
	// guide vers --certificat/--cle.
	refus := pousser(t, env, "x", nil)
	if refus.code != CodeAuthRefusee {
		t.Fatalf("sans certificat : code = %d, attendu %d (stderr : %s)", refus.code, CodeAuthRefusee, refus.stderr)
	}
	if !strings.Contains(refus.stderr, "certificat client") || !strings.Contains(refus.stderr, "--certificat") {
		t.Errorf("le refus doit guider vers le certificat client :\n%s", refus.stderr)
	}

	// AC étrangère : certificat client hors de auth.ac_clients, code 6.
	igcEtrangere := nouvelleIGCClients(t)
	certIntrus, cleIntrus := igcEtrangere.emettrePoste(t, "mallory")
	intrus := pousser(t, env, "x", []string{"--certificat", certIntrus, "--cle", cleIntrus})
	if intrus.code != CodeAuthRefusee {
		t.Fatalf("AC étrangère : code = %d, attendu %d (stderr : %s)", intrus.code, CodeAuthRefusee, intrus.stderr)
	}

	// « info » reste servie avant identité applicative, mais derrière la
	// poignée de main mTLS : sans certificat, code 6 également.
	info := executer(t, []string{"info", "--certificat", cheminCertificat, "--cle", cheminCle}, avecEnvironnement(env))
	if info.code != CodeOK || !strings.Contains(info.stdout, "AUTH-2") {
		t.Fatalf("info mTLS : code = %d\n%s\n%s", info.code, info.stdout, info.stderr)
	}
	infoSans := executer(t, []string{"info"}, avecEnvironnement(env))
	if infoSans.code != CodeAuthRefusee {
		t.Fatalf("info sans certificat : code = %d, attendu %d (stderr : %s)", infoSans.code, CodeAuthRefusee, infoSans.stderr)
	}
}

// TestIntegrationEpinglageAC : l'AC fournie est la seule autorité de
// confiance (TLS-1) — pointer une autre AC vaut refus de la connexion.
func TestIntegrationEpinglageAC(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	autreAC := nouvelleIGCClients(t).cheminCA
	env["ARDOISE_AC"] = autreAC
	r := pousser(t, env, "x", nil)
	if r.code != CodeInjoignable {
		t.Fatalf("AC épinglée étrangère : code = %d, attendu %d (stderr : %s)", r.code, CodeInjoignable, r.stderr)
	}
}

// TestIntegrationJetonRefus : sur une instance à jeton, l'absence de jeton
// et un jeton inconnu valent le code 6 ; le jeton n'apparaît jamais dans
// les sorties.
func TestIntegrationJetonRefus(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))

	sansJeton := map[string]string{"ARDOISE_ENDPOINT": env["ARDOISE_ENDPOINT"], "ARDOISE_AC": env["ARDOISE_AC"]}
	r := pousser(t, sansJeton, "x", nil)
	if r.code != CodeAuthRefusee {
		t.Fatalf("sans jeton : code = %d, attendu %d (stderr : %s)", r.code, CodeAuthRefusee, r.stderr)
	}
	if !strings.Contains(r.stderr, "jeton") {
		t.Errorf("le refus doit citer le jeton attendu :\n%s", r.stderr)
	}

	cheminFaux := filepath.Join(t.TempDir(), "jeton")
	if err := os.WriteFile(cheminFaux, []byte("jeton-inconnu-du-serveur\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mauvais := pousser(t, env, "x", []string{"--jeton", cheminFaux})
	if mauvais.code != CodeAuthRefusee {
		t.Fatalf("jeton inconnu : code = %d, attendu %d (stderr : %s)", mauvais.code, CodeAuthRefusee, mauvais.stderr)
	}
	if strings.Contains(mauvais.stderr, "jeton-inconnu-du-serveur") {
		t.Error("le jeton présenté ne doit jamais apparaître dans les sorties")
	}

	// L'option --jeton l'emporte et fonctionne : parcours nominal déjà
	// couvert par les tests d'intégration (ARDOISE_JETON) ; ici, via l'option.
	bon := pousser(t, map[string]string{"ARDOISE_ENDPOINT": env["ARDOISE_ENDPOINT"], "ARDOISE_AC": env["ARDOISE_AC"]},
		"contenu jeton", []string{"--jeton", env["ARDOISE_JETON"]})
	identifiantDe(t, bon)
}

// TestIntegrationJetonDroitsLarges : un fichier de jeton lisible par
// d'autres vaut un avertissement — l'opération aboutit.
func TestIntegrationJetonDroitsLarges(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	permissif := filepath.Join(t.TempDir(), "jeton")
	if err := os.WriteFile(permissif, []byte(jetonIntegration+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env["ARDOISE_JETON"] = permissif
	r := pousser(t, env, "contenu", nil)
	identifiantDe(t, r)
	if !strings.Contains(r.stderr, "avertissement") || !strings.Contains(r.stderr, "0600") {
		t.Errorf("avertissement sur les droits attendu :\n%s", r.stderr)
	}
}

// TestIntegrationJetonFichierInvalide : fichier absent ou vide, code 1.
func TestIntegrationJetonFichierInvalide(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	env["ARDOISE_JETON"] = filepath.Join(t.TempDir(), "absent")
	if r := pousser(t, env, "x", nil); r.code != CodeErreur {
		t.Errorf("fichier absent : code = %d, attendu %d", r.code, CodeErreur)
	}
	vide := filepath.Join(t.TempDir(), "jeton")
	if err := os.WriteFile(vide, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env["ARDOISE_JETON"] = vide
	if r := pousser(t, env, "x", nil); r.code != CodeErreur || !strings.Contains(r.stderr, "vide") {
		t.Errorf("fichier vide : code = %d, stderr = %q", r.code, r.stderr)
	}
}

// TestIntegrationDeclaratif : sur une instance déclarative, le client
// annonce de lui-même l'utilisateur et l'hôte (AUTH-4) — aucun matériel à
// fournir, aller-retour complet.
func TestIntegrationDeclaratif(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["auth"] = map[string]any{"mecanisme": "declaratif"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	r := pousser(t, env, "identité déclarée", nil)
	identifiant := identifiantDe(t, r)
	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK || lecture.stdout != "identité déclarée" {
		t.Fatalf("get déclaratif : code = %d, stdout = %q (stderr : %s)", lecture.code, lecture.stdout, lecture.stderr)
	}
}

// TestIntegrationPKCS11Stub : l'option est acceptée syntaxiquement mais
// refusée avec l'explication du dossier de risques.
func TestIntegrationPKCS11Stub(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	r := pousser(t, env, "x", []string{"--pkcs11", "pkcs11:token=carte-agent"})
	if r.code != CodeErreur {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeErreur, r.stderr)
	}
	if !strings.Contains(r.stderr, "PKCS#11 non pris en charge") || !strings.Contains(r.stderr, "cgo") {
		t.Errorf("message attendu :\n%s", r.stderr)
	}
	// Aussi refusé par « info » et par la variable d'environnement.
	env["ARDOISE_PKCS11"] = "pkcs11:token=carte-agent"
	if r := executer(t, []string{"info"}, avecEnvironnement(env)); r.code != CodeErreur ||
		!strings.Contains(r.stderr, "PKCS#11") {
		t.Errorf("info --pkcs11 : code = %d, stderr = %q", r.code, r.stderr)
	}
}

// TestIntegrationJetonJamaisEnClairDansLaTable vérifie l'hygiène de la
// table de test elle-même : elle ne contient que l'empreinte du jeton.
func TestIntegrationJetonJamaisEnClairDansLaTable(t *testing.T) {
	empreinte := sha256.Sum256([]byte(jetonIntegration))
	table := fmt.Sprintf(`{"alice.durand": %q}`, hex.EncodeToString(empreinte[:]))
	if strings.Contains(table, jetonIntegration) {
		t.Fatal("la table des jetons ne doit contenir que des empreintes")
	}
	if _, err := server.AnalyserJetons([]byte(table)); err != nil {
		t.Fatal(err)
	}
}
