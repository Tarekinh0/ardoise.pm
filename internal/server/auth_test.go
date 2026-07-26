package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/tlsconfig"
)

// igcTest est une IGC jetable : une AC racine et de quoi émettre des
// certificats clients pour les tests mTLS.
type igcTest struct {
	ca       *x509.Certificate
	cleCA    *ecdsa.PrivateKey
	cheminCA string
}

func nouvelleIGC(t *testing.T) *igcTest {
	t.Helper()
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "AC interne de test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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
	cheminCA := filepath.Join(t.TempDir(), "ac.pem")
	if err := os.WriteFile(cheminCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &igcTest{ca: ca, cleCA: cle, cheminCA: cheminCA}
}

// emettreClient émet un certificat client signé par l'AC, avec CN et SAN.
func (igc *igcTest) emettreClient(t *testing.T, cn string, emails, dns []string, uris []*url.URL) tls.Certificate {
	t.Helper()
	cle, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	modele := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: cn},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		EmailAddresses: emails,
		DNSNames:       dns,
		URIs:           uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, modele, igc.ca, &cle.PublicKey, igc.cleCA)
	if err != nil {
		t.Fatal(err)
	}
	feuille, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: cle, Leaf: feuille}
}

// certificatClient retourne le certificat x509 seul (pour forger r.TLS).
func (igc *igcTest) certificatClient(t *testing.T, cn string, emails, dns []string, uris []*url.URL) *x509.Certificate {
	t.Helper()
	return igc.emettreClient(t, cn, emails, dns, uris).Leaf
}

// instanceAuth construit une instance valide pour le mécanisme donné.
func instanceAuth(t *testing.T, mecanisme string, muter func(map[string]map[string]any)) *config.Instance {
	t.Helper()
	m := map[string]map[string]any{
		"instance":  {"nom": "ardoise-auth", "mode": "aveugle", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": mecanisme},
		"contenu":   {"chiffrement": "cle", "taille_max": "64Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"transport": {"certificat": "/tmp/inutilise.pem", "cle": "/tmp/inutilise.key"},
		"marquage":  {"actif": false},
	}
	switch mecanisme {
	case "mtls", "mtls-materiel":
		m["auth"]["ac_clients"] = "/etc/ardoise/ac-clients.pem"
	case "jeton":
		m["auth"]["jetons"] = "/etc/ardoise/jetons.json"
	}
	if muter != nil {
		muter(m)
	}
	donnees, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	inst, problemes, err := config.Analyser(donnees)
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes de configuration : %v", problemes)
	}
	return inst
}

// sonderIdentite exécute une requête au travers d'exigerIdentite et
// retourne l'identité vue par le handler aval (nil si refus).
func sonderIdentite(t *testing.T, inst *config.Instance, jetons *Jetons, preparer func(*http.Request)) (*Identite, *httptest.ResponseRecorder) {
	t.Helper()
	var identite *Identite
	sonde := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := IdentiteDepuisContexte(r.Context())
		if !ok {
			t.Error("identité absente du contexte derrière exigerIdentite")
		}
		identite = id
		w.WriteHeader(http.StatusNoContent)
	})
	requete := httptest.NewRequest(http.MethodPost, "/v1/ardoises", nil)
	if preparer != nil {
		preparer(requete)
	}
	enregistreur := httptest.NewRecorder()
	exigerIdentite(inst, jetons, nil, sonde).ServeHTTP(enregistreur, requete)
	return identite, enregistreur
}

func TestIdentiteCertificat(t *testing.T) {
	igc := nouvelleIGC(t)
	uri := &url.URL{Scheme: "spiffe", Host: "adm.interne", Path: "/alice"}
	complet := igc.certificatClient(t, "alice.durand", []string{"alice@adm.interne"}, []string{"poste-07.adm.interne"}, []*url.URL{uri})
	nu := igc.certificatClient(t, "", nil, nil, nil)

	cas := []struct {
		champ   string
		cert    *x509.Certificate
		attendu string
		erreur  bool
	}{
		{"CN", complet, "alice.durand", false},
		{"SAN:email", complet, "alice@adm.interne", false},
		{"SAN:dns", complet, "poste-07.adm.interne", false},
		{"SAN:uri", complet, "spiffe://adm.interne/alice", false},
		{"CN", nu, "", true},
		{"SAN:email", nu, "", true},
		{"SAN:dns", nu, "", true},
		{"SAN:uri", nu, "", true},
		{"OU", complet, "", true},
	}
	for _, c := range cas {
		obtenu, err := identiteCertificat(c.cert, c.champ)
		if c.erreur {
			if err == nil {
				t.Errorf("champ %s : erreur attendue, obtenu %q", c.champ, obtenu)
			}
			continue
		}
		if err != nil || obtenu != c.attendu {
			t.Errorf("champ %s : obtenu %q (err %v), attendu %q", c.champ, obtenu, err, c.attendu)
		}
	}
}

func TestExigerIdentiteMTLS(t *testing.T) {
	igc := nouvelleIGC(t)
	inst := instanceAuth(t, "mtls", nil)

	// Certificat présenté : identité extraite du CN, mécanisme « certificat ».
	cert := igc.certificatClient(t, "alice.durand", []string{"alice@adm.interne"}, nil, nil)
	identite, enregistreur := sonderIdentite(t, inst, nil, func(r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	})
	if enregistreur.Code != http.StatusNoContent {
		t.Fatalf("statut = %d, corps %s", enregistreur.Code, enregistreur.Body)
	}
	if identite == nil || identite.Utilisateur != "alice.durand" || identite.Mecanisme != MecanismeCertificat || identite.Hote != "" {
		t.Fatalf("identité = %+v", identite)
	}

	// Champ SAN:email.
	inst.Auth.ChampIdentite = "SAN:email"
	identite, _ = sonderIdentite(t, inst, nil, func(r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	})
	if identite == nil || identite.Utilisateur != "alice@adm.interne" {
		t.Fatalf("identité SAN:email = %+v", identite)
	}

	// AUTH-1 : même contrôle serveur que AUTH-2.
	materiel := instanceAuth(t, "mtls-materiel", nil)
	identite, _ = sonderIdentite(t, materiel, nil, func(r *http.Request) {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	})
	if identite == nil || identite.Mecanisme != MecanismeCertificat {
		t.Fatalf("identité mtls-materiel = %+v", identite)
	}

	// Aucun certificat : 401, forme d'erreur JSON de l'API.
	identite, enregistreur = sonderIdentite(t, inst, nil, nil)
	if identite != nil || enregistreur.Code != http.StatusUnauthorized {
		t.Fatalf("statut = %d, identité %+v", enregistreur.Code, identite)
	}
	if enveloppe := decoderErreurAPI(t, enregistreur.Body.Bytes()); enveloppe.Erreur.Code != "authentification_requise" {
		t.Errorf("erreur = %+v", enveloppe)
	}
}

func TestExigerIdentiteJeton(t *testing.T) {
	jetonValide := "jeton-de-test-alice"
	empreinte := sha256.Sum256([]byte(jetonValide))
	jetons, err := AnalyserJetons([]byte(fmt.Sprintf(`{"alice.durand": %q}`, hex.EncodeToString(empreinte[:]))))
	if err != nil {
		t.Fatal(err)
	}
	inst := instanceAuth(t, "jeton", nil)

	identite, enregistreur := sonderIdentite(t, inst, jetons, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+jetonValide)
	})
	if enregistreur.Code != http.StatusNoContent {
		t.Fatalf("statut = %d", enregistreur.Code)
	}
	if identite == nil || identite.Utilisateur != "alice.durand" || identite.Mecanisme != MecanismeJeton {
		t.Fatalf("identité = %+v", identite)
	}

	for nom, preparer := range map[string]func(*http.Request){
		"jeton absent":    nil,
		"jeton inconnu":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer autre-jeton") },
		"schema basic":    func(r *http.Request) { r.Header.Set("Authorization", "Basic YWxpY2U6c2VjcmV0") },
		"bearer vide":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"empreinte brute": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+hex.EncodeToString(empreinte[:])) },
	} {
		identite, enregistreur := sonderIdentite(t, inst, jetons, preparer)
		if identite != nil || enregistreur.Code != http.StatusUnauthorized {
			t.Errorf("%s : statut = %d, identité %+v", nom, enregistreur.Code, identite)
			continue
		}
		// Le 401 de jeton porte WWW-Authenticate (RFC 6750).
		if enregistreur.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s : en-tête WWW-Authenticate absent", nom)
		}
	}
}

func TestExigerIdentiteDeclaratif(t *testing.T) {
	inst := instanceAuth(t, "declaratif", nil)

	identite, enregistreur := sonderIdentite(t, inst, nil, func(r *http.Request) {
		r.Header.Set("X-Ardoise-Utilisateur", "alice.durand")
		r.Header.Set("X-Ardoise-Hote", "poste-adm-07.zone_a")
	})
	if enregistreur.Code != http.StatusNoContent {
		t.Fatalf("statut = %d", enregistreur.Code)
	}
	if identite == nil || identite.Utilisateur != "alice.durand" ||
		identite.Hote != "poste-adm-07.zone_a" || identite.Mecanisme != MecanismeDeclaratif {
		t.Fatalf("identité = %+v", identite)
	}

	for nom, preparer := range map[string]func(*http.Request){
		"aucun en-tête": nil,
		"hôte manquant": func(r *http.Request) { r.Header.Set("X-Ardoise-Utilisateur", "alice.durand") },
		"utilisateur manquant": func(r *http.Request) {
			r.Header.Set("X-Ardoise-Hote", "poste-adm-07")
		},
		"majuscules refusées": func(r *http.Request) {
			r.Header.Set("X-Ardoise-Utilisateur", "Alice.Durand")
			r.Header.Set("X-Ardoise-Hote", "poste-adm-07")
		},
		"caractères hors alphabet": func(r *http.Request) {
			r.Header.Set("X-Ardoise-Utilisateur", "alice durand")
			r.Header.Set("X-Ardoise-Hote", "poste-adm-07")
		},
		"au-delà de 64 caractères": func(r *http.Request) {
			r.Header.Set("X-Ardoise-Utilisateur", strings.Repeat("a", 65))
			r.Header.Set("X-Ardoise-Hote", "poste-adm-07")
		},
	} {
		identite, enregistreur := sonderIdentite(t, inst, nil, preparer)
		if identite != nil || enregistreur.Code != http.StatusUnauthorized {
			t.Errorf("%s : statut = %d, identité %+v", nom, enregistreur.Code, identite)
		}
	}
}

// TestAucunAccesAnonyme vérifie, pour chaque mécanisme, que dépôt et
// récupération sans matériel d'identification reçoivent 401 (ADR-009),
// tandis que GET /v1/politique reste servie avant authentification.
func TestAucunAccesAnonyme(t *testing.T) {
	jetons, err := AnalyserJetons([]byte(fmt.Sprintf(`{"a": %q}`, strings.Repeat("00", 32))))
	if err != nil {
		t.Fatal(err)
	}
	for _, mecanisme := range []string{"mtls", "mtls-materiel", "jeton", "declaratif"} {
		t.Run(mecanisme, func(t *testing.T) {
			inst := instanceAuth(t, mecanisme, nil)
			serveur := httptest.NewServer(Handler(inst, magasinDeTest(t), jetons, Dependances{}))
			t.Cleanup(serveur.Close)

			depot, err := http.Post(serveur.URL+"/v1/ardoises", "application/json", strings.NewReader(`{"contenu":"AQ=="}`))
			if err != nil {
				t.Fatal(err)
			}
			corps, _ := io.ReadAll(depot.Body)
			depot.Body.Close()
			if depot.StatusCode != http.StatusUnauthorized {
				t.Errorf("dépôt anonyme : statut = %d, attendu 401", depot.StatusCode)
			}
			if enveloppe := decoderErreurAPI(t, corps); enveloppe.Erreur.Code != "authentification_requise" {
				t.Errorf("dépôt anonyme : erreur = %+v", enveloppe)
			}

			lecture, err := http.Get(serveur.URL + "/v1/ardoises/abcdefghij29")
			if err != nil {
				t.Fatal(err)
			}
			lecture.Body.Close()
			if lecture.StatusCode != http.StatusUnauthorized {
				t.Errorf("lecture anonyme : statut = %d, attendu 401", lecture.StatusCode)
			}

			politique, err := http.Get(serveur.URL + "/v1/politique")
			if err != nil {
				t.Fatal(err)
			}
			var p config.Politique
			err = json.NewDecoder(politique.Body).Decode(&p)
			politique.Body.Close()
			if politique.StatusCode != http.StatusOK || err != nil {
				t.Fatalf("politique avant authentification : statut = %d (err %v)", politique.StatusCode, err)
			}
			if p.Identification != mecanisme {
				t.Errorf("politique.identification = %q, attendu %q", p.Identification, mecanisme)
			}
		})
	}
}

func TestChargerJetons(t *testing.T) {
	rep := t.TempDir()
	empreinte := strings.Repeat("ab", 32)
	contenu := fmt.Sprintf(`{"alice.durand": %q}`, empreinte)

	chemin := filepath.Join(rep, "jetons.json")
	if err := os.WriteFile(chemin, []byte(contenu), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerJetons(chemin); err != nil {
		t.Fatalf("table valide refusée : %v", err)
	}

	// Droits trop larges : refus de démarrage, pas un avertissement.
	permissif := filepath.Join(rep, "permissif.json")
	if err := os.WriteFile(permissif, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ChargerJetons(permissif); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("droits 0644 : refus attendu, obtenu %v", err)
	}

	if _, err := ChargerJetons(filepath.Join(rep, "absent.json")); err == nil {
		t.Fatal("fichier absent : refus attendu")
	}

	for nom, donnees := range map[string]string{
		"vide":               `{}`,
		"identité vide":      fmt.Sprintf(`{"": %q}`, empreinte),
		"empreinte courte":   `{"alice": "abcd"}`,
		"empreinte non hexa": fmt.Sprintf(`{"alice": %q}`, strings.Repeat("zz", 32)),
		"JSON illisible":     `{`,
		"liste":              `["alice"]`,
	} {
		if _, err := AnalyserJetons([]byte(donnees)); err == nil {
			t.Errorf("%s : refus attendu", nom)
		}
	}
}

// TestJetonsComparaisonParEmpreinte vérifie que la recherche passe par
// l'empreinte SHA-256 du jeton présenté, comparée en temps constant : le
// jeton exact correspond, l'empreinte elle-même (64 hexadécimaux) non.
func TestJetonsComparaisonParEmpreinte(t *testing.T) {
	jeton := []byte("jeton-tres-secret")
	empreinte := sha256.Sum256(jeton)
	jetons, err := AnalyserJetons([]byte(fmt.Sprintf(
		`{"alice.durand": %q, "bruno.marchal": %q}`,
		hex.EncodeToString(empreinte[:]), strings.Repeat("cd", 32))))
	if err != nil {
		t.Fatal(err)
	}
	if identite, ok := jetons.Identite(jeton); !ok || identite != "alice.durand" {
		t.Fatalf("identité = %q (%v)", identite, ok)
	}
	for nom, faux := range map[string][]byte{
		"jeton inconnu":       []byte("autre"),
		"empreinte présentée": []byte(hex.EncodeToString(empreinte[:])),
		"préfixe du jeton":    jeton[:len(jeton)-1],
		"jeton vide":          {},
	} {
		if identite, ok := jetons.Identite(faux); ok {
			t.Errorf("%s : accepté comme %q", nom, identite)
		}
	}
}

// TestMTLSBoutEnBout couvre la poignée de main complète : l'instance exige
// et vérifie le certificat client contre auth.ac_clients ; un certificat de
// la bonne AC passe, l'absence de certificat et une AC étrangère échouent.
func TestMTLSBoutEnBout(t *testing.T) {
	igcClients := nouvelleIGC(t)
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceAuth(t, "mtls", func(m map[string]map[string]any) {
		m["auth"]["ac_clients"] = igcClients.cheminCA
		m["transport"] = map[string]any{"certificat": cheminCertificat, "cle": cheminCle}
	})

	serveur, err := Nouveau(inst, "127.0.0.1:0")
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

	pemServeur, err := os.ReadFile(cheminCertificat)
	if err != nil {
		t.Fatal(err)
	}
	acServeur := x509.NewCertPool()
	acServeur.AppendCertsFromPEM(pemServeur)
	base := "https://" + serveur.Adresse()

	clientHTTP := func(certificats ...tls.Certificate) *http.Client {
		return &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs:      acServeur,
				Certificates: certificats,
				MinVersion:   tls.VersionTLS12,
			}},
		}
	}

	// Bonne AC : dépôt puis lecture aboutissent.
	habilite := clientHTTP(igcClients.emettreClient(t, "alice.durand", nil, nil, nil))
	depot, err := habilite.Post(base+"/v1/ardoises", "application/json", strings.NewReader(`{"contenu":"AQID"}`))
	if err != nil {
		t.Fatalf("dépôt mTLS : %v", err)
	}
	corps, _ := io.ReadAll(depot.Body)
	depot.Body.Close()
	if depot.StatusCode != http.StatusCreated {
		t.Fatalf("dépôt mTLS : statut = %d, corps %s", depot.StatusCode, corps)
	}
	var reponse reponseDepot
	if err := json.Unmarshal(corps, &reponse); err != nil {
		t.Fatal(err)
	}
	lecture, err := habilite.Get(base + "/v1/ardoises/" + reponse.ID)
	if err != nil {
		t.Fatalf("lecture mTLS : %v", err)
	}
	lecture.Body.Close()
	if lecture.StatusCode != http.StatusOK {
		t.Fatalf("lecture mTLS : statut = %d", lecture.StatusCode)
	}

	// Sans certificat : la poignée de main (TLS 1.2) ou la première requête
	// (TLS 1.3, alerte différée) échoue — jamais de réponse HTTP.
	if reponse, err := clientHTTP().Get(base + "/v1/politique"); err == nil {
		reponse.Body.Close()
		t.Fatal("client sans certificat accepté par une instance mTLS")
	}

	// AC étrangère : certificat syntaxiquement valide mais hors
	// auth.ac_clients, refusé par la vérification de chaîne.
	igcEtrangere := nouvelleIGC(t)
	intrus := clientHTTP(igcEtrangere.emettreClient(t, "mallory", nil, nil, nil))
	if reponse, err := intrus.Get(base + "/v1/politique"); err == nil {
		reponse.Body.Close()
		t.Fatal("certificat d'une AC étrangère accepté")
	}
}

// TestVersionTLSMinimale vérifie que la version minimale configurée est
// appliquée : en version_min 1.3, aucune poignée de main 1.2 n'aboutit ;
// en version_min 1.2, les suites sont restreintes à la liste ANSSI.
func TestVersionTLSMinimale(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	demarrer := func(versionMin string) (adresse string) {
		t.Helper()
		inst := instanceAuth(t, "declaratif", func(m map[string]map[string]any) {
			m["transport"] = map[string]any{"certificat": cheminCertificat, "cle": cheminCle, "version_min": versionMin}
		})
		serveur, err := Nouveau(inst, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if versionMin == "1.3" {
			if serveur.serveurHTTP.TLSConfig.MinVersion != tls.VersionTLS13 {
				t.Errorf("version minimale = %x, attendu TLS 1.3", serveur.serveurHTTP.TLSConfig.MinVersion)
			}
			// Les suites imposées ne concernent que le repli 1.2 : en 1.3,
			// le protocole fixe lui-même ses suites.
			if serveur.serveurHTTP.TLSConfig.CipherSuites != nil {
				t.Error("aucune liste de suites ne doit être posée en version_min 1.3")
			}
		} else if len(serveur.serveurHTTP.TLSConfig.CipherSuites) == 0 {
			t.Error("les suites ANSSI doivent être posées en version_min 1.2")
		}
		if err := serveur.Ecouter(); err != nil {
			t.Fatal(err)
		}
		ctx, annuler := context.WithCancel(context.Background())
		termine := make(chan error, 1)
		go func() { termine <- serveur.Servir(ctx) }()
		t.Cleanup(func() {
			annuler()
			<-termine
		})
		return serveur.Adresse()
	}

	pemServeur, err := os.ReadFile(cheminCertificat)
	if err != nil {
		t.Fatal(err)
	}
	ac := x509.NewCertPool()
	ac.AppendCertsFromPEM(pemServeur)

	// version_min 1.3 : un client plafonné à 1.2 est refusé.
	adresse13 := demarrer("1.3")
	conn, err := tls.Dial("tcp", adresse13, &tls.Config{RootCAs: ac, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err == nil {
		conn.Close()
		t.Fatal("poignée de main TLS 1.2 acceptée malgré version_min 1.3")
	}

	// version_min 1.2 : la poignée de main 1.2 aboutit, sur une suite ANSSI.
	adresse12 := demarrer("1.2")
	conn, err = tls.Dial("tcp", adresse12, &tls.Config{RootCAs: ac, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("poignée de main TLS 1.2 refusée malgré version_min 1.2 : %v", err)
	}
	defer conn.Close()
	suite := conn.ConnectionState().CipherSuite
	admise := false
	for _, s := range tlsconfig.SuitesTLS12() {
		if s == suite {
			admise = true
		}
	}
	if !admise {
		t.Errorf("suite négociée %s hors de la liste ANSSI", tls.CipherSuiteName(suite))
	}
}

// TestJetonInvalideBoutEnBout : au travers du Handler complet, un jeton
// valide dépose, un jeton inconnu et l'absence de jeton reçoivent 401.
func TestJetonBoutEnBout(t *testing.T) {
	jetonValide := "jeton-bout-en-bout"
	empreinte := sha256.Sum256([]byte(jetonValide))
	jetons, err := AnalyserJetons([]byte(fmt.Sprintf(`{"alice.durand": %q}`, hex.EncodeToString(empreinte[:]))))
	if err != nil {
		t.Fatal(err)
	}
	inst := instanceAuth(t, "jeton", nil)
	serveur := httptest.NewServer(Handler(inst, magasinDeTest(t), jetons, Dependances{}))
	t.Cleanup(serveur.Close)

	deposerAvec := func(autorisation string) int {
		t.Helper()
		requete, err := http.NewRequest(http.MethodPost, serveur.URL+"/v1/ardoises", strings.NewReader(`{"contenu":"AQ=="}`))
		if err != nil {
			t.Fatal(err)
		}
		requete.Header.Set("Content-Type", "application/json")
		if autorisation != "" {
			requete.Header.Set("Authorization", autorisation)
		}
		reponse, err := http.DefaultClient.Do(requete)
		if err != nil {
			t.Fatal(err)
		}
		reponse.Body.Close()
		return reponse.StatusCode
	}

	if statut := deposerAvec("Bearer " + jetonValide); statut != http.StatusCreated {
		t.Errorf("jeton valide : statut = %d, attendu 201", statut)
	}
	if statut := deposerAvec("Bearer intrus"); statut != http.StatusUnauthorized {
		t.Errorf("jeton inconnu : statut = %d, attendu 401", statut)
	}
	if statut := deposerAvec(""); statut != http.StatusUnauthorized {
		t.Errorf("jeton absent : statut = %d, attendu 401", statut)
	}
}
