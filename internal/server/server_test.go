package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/store"
)

// genererMaterielTLS produit un certificat auto-signé (AC et serveur à la
// fois) et sa clé, valables pour 127.0.0.1 et localhost, dans t.TempDir().
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

func instanceDeTest(t *testing.T, cheminCertificat, cheminCle string) *config.Instance {
	t.Helper()
	// Identification déclarative : les tests du cycle de vie passent par
	// les en-têtes X-Ardoise-* (voir requeteIdentifiee) ; les mécanismes
	// mtls et jeton ont leurs propres tests dans auth_test.go.
	donnees := fmt.Sprintf(`{
		"instance":  {"nom": "ardoise-test", "mode": "aveugle", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": "declaratif"},
		"contenu":   {"chiffrement": "cle", "taille_max": "256Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"journal":   {"destination": "syslog+tls://journal.interne:6514", "chainage": true},
		"transport": {"certificat": %q, "cle": %q, "version_min": "1.3"},
		"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"}
	}`, cheminCertificat, cheminCle)
	inst, problemes, err := config.Analyser([]byte(donnees))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}
	return inst
}

func decoderErreurAPI(t *testing.T, corps []byte) enveloppeErreur {
	t.Helper()
	var enveloppe enveloppeErreur
	if err := json.Unmarshal(corps, &enveloppe); err != nil {
		t.Fatalf("corps d'erreur illisible %q : %v", corps, err)
	}
	return enveloppe
}

// magasinDeTest crée un magasin mémoire fermé avec le test.
func magasinDeTest(t *testing.T) store.Magasin {
	t.Helper()
	magasin := store.NouveauMemoire(context.Background(), time.Hour)
	t.Cleanup(func() { magasin.Fermer() })
	return magasin
}

// serveurDeTest monte le Handler complet sur un serveur httptest.
func serveurDeTest(t *testing.T, muterInstance func(*config.Instance)) (*httptest.Server, store.Magasin) {
	t.Helper()
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	if muterInstance != nil {
		muterInstance(inst)
	}
	magasin := magasinDeTest(t)
	serveur := httptest.NewServer(Handler(inst, magasin, nil, Dependances{}))
	t.Cleanup(serveur.Close)
	return serveur, magasin
}

// requeteIdentifiee exécute une requête portant l'identité déclarée de test
// (le serveur de test retient l'identification déclarative).
func requeteIdentifiee(t *testing.T, methode, url string, corps io.Reader) (*http.Response, []byte) {
	t.Helper()
	requete, err := http.NewRequest(methode, url, corps)
	if err != nil {
		t.Fatal(err)
	}
	if corps != nil {
		requete.Header.Set("Content-Type", "application/json")
	}
	requete.Header.Set("X-Ardoise-Utilisateur", "alice.durand")
	requete.Header.Set("X-Ardoise-Hote", "poste-adm-07")
	reponse, err := http.DefaultClient.Do(requete)
	if err != nil {
		t.Fatal(err)
	}
	defer reponse.Body.Close()
	donnees, err := io.ReadAll(reponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reponse, donnees
}

// deposer envoie un dépôt JSON identifié et retourne la réponse décodée.
func deposer(t *testing.T, url string, corps string) (*http.Response, []byte) {
	t.Helper()
	return requeteIdentifiee(t, http.MethodPost, url+"/v1/ardoises", strings.NewReader(corps))
}

// recuperer lit une ardoise avec l'identité déclarée de test.
func recuperer(t *testing.T, url, id string) (*http.Response, []byte) {
	t.Helper()
	return requeteIdentifiee(t, http.MethodGet, url+"/v1/ardoises/"+id, nil)
}

func TestHandlerPolitique(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil)

	reponse, err := http.Get(serveur.URL + "/v1/politique")
	if err != nil {
		t.Fatal(err)
	}
	defer reponse.Body.Close()
	if reponse.StatusCode != http.StatusOK {
		t.Fatalf("statut = %d", reponse.StatusCode)
	}
	if ct := reponse.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	var politique config.Politique
	if err := json.NewDecoder(reponse.Body).Decode(&politique); err != nil {
		t.Fatal(err)
	}
	if politique.Instance != "ardoise-test" || politique.Mode != config.ModeAveugle {
		t.Errorf("politique inattendue : %+v", politique)
	}
	if len(politique.Options) != 9 {
		t.Errorf("9 options attendues, obtenu %d", len(politique.Options))
	}
	if o, ok := politique.Option(config.DimIdentification); !ok || o.ID != "AUTH-4" {
		t.Errorf("identification = %+v", o)
	}
	if politique.Identification != "declaratif" {
		t.Errorf("identification = %q : la politique doit annoncer le mécanisme au client", politique.Identification)
	}
}

func TestDepotEtRecuperationHTTP(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil)
	chiffre := []byte{0x01, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	corps := fmt.Sprintf(`{"contenu": %q, "duree": "2h", "lecture_unique": false, "marquage_complement": "incident 7"}`,
		base64.StdEncoding.EncodeToString(chiffre))

	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d, corps %s", reponse.StatusCode, donnees)
	}
	var depot reponseDepot
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}
	if len(depot.ID) != 12 {
		t.Errorf("id = %q", depot.ID)
	}
	if attendu := crypto.Empreinte(chiffre); depot.Empreinte != attendu {
		t.Errorf("empreinte = %s, attendu %s", depot.Empreinte, attendu)
	}
	echeance, err := time.Parse(time.RFC3339, depot.Echeance)
	if err != nil {
		t.Fatalf("échéance illisible %q : %v", depot.Echeance, err)
	}
	if restant := time.Until(echeance); restant < time.Hour || restant > 2*time.Hour {
		t.Errorf("échéance à %s de maintenant, attendu ≈ 2h", restant)
	}

	lecture, corpsLecture := recuperer(t, serveur.URL, depot.ID)
	if lecture.StatusCode != http.StatusOK {
		t.Fatalf("statut de lecture = %d", lecture.StatusCode)
	}
	var ardoise reponseArdoise
	if err := json.Unmarshal(corpsLecture, &ardoise); err != nil {
		t.Fatal(err)
	}
	rendu, err := base64.StdEncoding.DecodeString(ardoise.Contenu)
	if err != nil || !bytes.Equal(rendu, chiffre) {
		t.Fatalf("contenu rendu = %q (err %v)", ardoise.Contenu, err)
	}
	if ardoise.Empreinte != depot.Empreinte || ardoise.LectureUnique {
		t.Errorf("ardoise = %+v", ardoise)
	}
	if !ardoise.Marquage.Actif || ardoise.Marquage.Libelle != "DIFFUSION RESTREINTE" || ardoise.Marquage.Complement != "incident 7" {
		t.Errorf("marquage = %+v", ardoise.Marquage)
	}
}

func TestDepotDureeRefusee(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil) // duree_max = 24h
	corps := fmt.Sprintf(`{"contenu": %q, "duree": "48h"}`, base64.StdEncoding.EncodeToString([]byte{0x01}))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("statut = %d, attendu 422", reponse.StatusCode)
	}
	if enveloppe := decoderErreurAPI(t, donnees); enveloppe.Erreur.Code != "duree_refusee" {
		t.Errorf("erreur = %+v", enveloppe)
	}
}

func TestDepotDureeParDefaut(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil) // duree_defaut = 1h
	corps := fmt.Sprintf(`{"contenu": %q}`, base64.StdEncoding.EncodeToString([]byte{0x01}))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d", reponse.StatusCode)
	}
	var depot reponseDepot
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}
	echeance, err := time.Parse(time.RFC3339, depot.Echeance)
	if err != nil {
		t.Fatal(err)
	}
	if restant := time.Until(echeance); restant < 55*time.Minute || restant > time.Hour {
		t.Errorf("échéance à %s de maintenant, attendu ≈ 1h (durée par défaut)", restant)
	}
}

func TestDepotTailleDepassee(t *testing.T) {
	serveur, _ := serveurDeTest(t, func(inst *config.Instance) {
		inst.Contenu.TailleMax = 1024
		inst.Contenu.TailleMaxTexte = "1Kio"
	})
	// La marge de chiffrement la plus large est celle de CHIF-MD
	// (~7 Kio) ; le contenu testé doit la dépasser pour déclencher
	// un refus 413. Ici, 9 Kio excède 1 Kio + margeChiffrement.
	gros := bytes.Repeat([]byte{0x42}, 9216)
	corps := fmt.Sprintf(`{"contenu": %q}`, base64.StdEncoding.EncodeToString(gros))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("statut = %d, attendu 413", reponse.StatusCode)
	}
	if enveloppe := decoderErreurAPI(t, donnees); enveloppe.Erreur.Code != "taille_depassee" {
		t.Errorf("erreur = %+v", enveloppe)
	}

	// Le surcoût du chiffrement au-delà de taille_max reste admis.
	limite := bytes.Repeat([]byte{0x42}, 1024+45)
	corps = fmt.Sprintf(`{"contenu": %q}`, base64.StdEncoding.EncodeToString(limite))
	if reponse, donnees := deposer(t, serveur.URL, corps); reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d (%s) : la marge de chiffrement doit être admise", reponse.StatusCode, donnees)
	}
}

func TestDepotRequeteInvalide(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil)
	for nom, corps := range map[string]string{
		"JSON illisible":  `{`,
		"champ inconnu":   `{"contenu": "AQ==", "listing": true}`,
		"base64 invalide": `{"contenu": "%%%"}`,
		"contenu vide":    `{"contenu": ""}`,
	} {
		reponse, donnees := deposer(t, serveur.URL, corps)
		if reponse.StatusCode != http.StatusBadRequest {
			t.Errorf("%s : statut = %d, attendu 400", nom, reponse.StatusCode)
			continue
		}
		if enveloppe := decoderErreurAPI(t, donnees); enveloppe.Erreur.Code != "requete_invalide" {
			t.Errorf("%s : erreur = %+v", nom, enveloppe)
		}
	}
}

func TestDepotLectureUniqueInterdite(t *testing.T) {
	serveur, _ := serveurDeTest(t, func(inst *config.Instance) {
		inst.Retention.LectureUnique = config.LectureUniqueInterdit
	})
	corps := fmt.Sprintf(`{"contenu": %q, "lecture_unique": true}`, base64.StdEncoding.EncodeToString([]byte{0x01}))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("statut = %d, attendu 422", reponse.StatusCode)
	}
	if enveloppe := decoderErreurAPI(t, donnees); enveloppe.Erreur.Code != "lecture_unique_refusee" {
		t.Errorf("erreur = %+v", enveloppe)
	}
}

func TestDepotPourRefuseSousDeclaratif(t *testing.T) {
	// Instance déclarative (celle des tests) : refus pérenne, l'identité du
	// lecteur étant falsifiable — la prise en charge de « pour » ailleurs
	// n'y change rien.
	serveur, _ := serveurDeTest(t, nil)
	corps := fmt.Sprintf(`{"contenu": %q, "pour": ["alice.durand"]}`, base64.StdEncoding.EncodeToString([]byte{0x01}))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("statut = %d, attendu 422", reponse.StatusCode)
	}
	enveloppe := decoderErreurAPI(t, donnees)
	if enveloppe.Erreur.Code != "option_refusee" {
		t.Errorf("erreur = %+v", enveloppe)
	}
	if !strings.Contains(enveloppe.Erreur.Message, "déclarative") {
		t.Errorf("le refus déclaratif doit être motivé : %+v", enveloppe.Erreur)
	}
}

func TestDepotPourAccepteSousAuthentification(t *testing.T) {
	// Instance authentifiée (handler appelé directement, hors middleware) :
	// « pour » est accepté, validé et conservé avec l'ardoise.
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Auth.Mecanisme = "mtls"
	magasin := magasinDeTest(t)
	corps := fmt.Sprintf(`{"contenu": %q, "pour": ["alice.durand", "@equipe-reseau"]}`, base64.StdEncoding.EncodeToString([]byte{0x01}))
	requete := httptest.NewRequest(http.MethodPost, "/v1/ardoises", strings.NewReader(corps))
	enregistreur := httptest.NewRecorder()
	deposerArdoise(inst, magasin, Dependances{}).ServeHTTP(enregistreur, requete)
	if enregistreur.Code != http.StatusCreated {
		t.Fatalf("statut = %d, attendu 201 (%s)", enregistreur.Code, enregistreur.Body.String())
	}
	var depot reponseDepot
	if err := json.Unmarshal(enregistreur.Body.Bytes(), &depot); err != nil {
		t.Fatal(err)
	}
	a, err := magasin.Recuperer(depot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Pour) != 2 || a.Pour[0] != "alice.durand" || a.Pour[1] != "@equipe-reseau" {
		t.Errorf("Pour = %v", a.Pour)
	}
}

func TestDepotPourEntreesInvalides(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Auth.Mecanisme = "mtls"
	cas := map[string]string{
		"identité malformée": `["alice durand"]`,
		"majuscules":         `["Alice.Durand"]`,
		"groupe vide":        `["@"]`,
		"entrée vide":        `[""]`,
	}
	for nom, pour := range cas {
		t.Run(nom, func(t *testing.T) {
			corps := fmt.Sprintf(`{"contenu": %q, "pour": %s}`, base64.StdEncoding.EncodeToString([]byte{0x01}), pour)
			requete := httptest.NewRequest(http.MethodPost, "/v1/ardoises", strings.NewReader(corps))
			enregistreur := httptest.NewRecorder()
			deposerArdoise(inst, magasinDeTest(t), Dependances{}).ServeHTTP(enregistreur, requete)
			if enregistreur.Code != http.StatusUnprocessableEntity {
				t.Fatalf("statut = %d, attendu 422", enregistreur.Code)
			}
			if enveloppe := decoderErreurAPI(t, enregistreur.Body.Bytes()); enveloppe.Erreur.Code != "option_refusee" {
				t.Errorf("erreur = %+v", enveloppe)
			}
		})
	}
}

// TestLectureUniqueImposeeRET1 vérifie que RET-1 impose la destruction à la
// première lecture quel que soit le choix du client.
func TestLectureUniqueImposeeRET1(t *testing.T) {
	serveur, _ := serveurDeTest(t, func(inst *config.Instance) {
		inst.Retention.LectureUnique = config.LectureUniqueImposee
	})
	corps := fmt.Sprintf(`{"contenu": %q, "lecture_unique": false}`, base64.StdEncoding.EncodeToString([]byte{0x01, 0x02}))
	reponse, donnees := deposer(t, serveur.URL, corps)
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d", reponse.StatusCode)
	}
	var depot reponseDepot
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}

	premiere, corpsPremiere := recuperer(t, serveur.URL, depot.ID)
	var ardoise reponseArdoise
	if err := json.Unmarshal(corpsPremiere, &ardoise); err != nil {
		t.Fatal(err)
	}
	if premiere.StatusCode != http.StatusOK || !ardoise.LectureUnique {
		t.Fatalf("première lecture : statut %d, lecture_unique %v", premiere.StatusCode, ardoise.LectureUnique)
	}

	seconde, _ := recuperer(t, serveur.URL, depot.ID)
	if seconde.StatusCode != http.StatusNotFound {
		t.Fatalf("seconde lecture : statut = %d, attendu 404 (consommée)", seconde.StatusCode)
	}
}

// TestCode5Indistinguable vérifie que absente, expirée, consommée et
// malformée reçoivent une réponse strictement identique (statut, code,
// message).
func TestCode5Indistinguable(t *testing.T) {
	serveur, magasin := serveurDeTest(t, nil)

	// Consommée.
	if err := magasin.Deposer(&store.Ardoise{
		ID: "abcdefghij42", Chiffre: []byte{0x01}, Echeance: time.Now().Add(time.Hour), LectureUnique: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := magasin.Recuperer("abcdefghij42"); err != nil {
		t.Fatal(err)
	}
	// Expirée.
	if err := magasin.Deposer(&store.Ardoise{
		ID: "abcdefghij43", Chiffre: []byte{0x01}, Echeance: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatal(err)
	}

	var references []string
	for _, id := range []string{"abcdefghij44", "abcdefghij42", "abcdefghij43", "IDENTIFIANT-MALFORME"} {
		reponse, corps := recuperer(t, serveur.URL, id)
		if reponse.StatusCode != http.StatusNotFound {
			t.Fatalf("id %q : statut = %d, attendu 404", id, reponse.StatusCode)
		}
		references = append(references, string(corps))
	}
	for i := 1; i < len(references); i++ {
		if references[i] != references[0] {
			t.Fatalf("réponses code 5 distinguables :\n%q\n%q", references[0], references[i])
		}
	}
	if !strings.Contains(references[0], "ardoise inexistante, expirée ou déjà consommée") {
		t.Fatalf("message code 5 inattendu : %q", references[0])
	}
}

func TestHandlerRouteEtMethodeInconnues(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil)

	reponse, err := http.Get(serveur.URL + "/v1/inconnu")
	if err != nil {
		t.Fatal(err)
	}
	var corps [512]byte
	n, _ := reponse.Body.Read(corps[:])
	reponse.Body.Close()
	if reponse.StatusCode != http.StatusNotFound {
		t.Errorf("route inconnue : statut = %d, attendu 404", reponse.StatusCode)
	}
	if enveloppe := decoderErreurAPI(t, corps[:n]); enveloppe.Erreur.Code != "introuvable" {
		t.Errorf("erreur 404 inattendue : %+v", enveloppe)
	}

	requete, _ := http.NewRequest(http.MethodDelete, serveur.URL+"/v1/politique", nil)
	reponse, err = http.DefaultClient.Do(requete)
	if err != nil {
		t.Fatal(err)
	}
	n, _ = reponse.Body.Read(corps[:])
	reponse.Body.Close()
	if reponse.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("méthode refusée : statut = %d, attendu 405", reponse.StatusCode)
	}
	if enveloppe := decoderErreurAPI(t, corps[:n]); enveloppe.Erreur.Code != "methode_refusee" {
		t.Errorf("erreur 405 inattendue : %+v", enveloppe)
	}
}

func TestNouveauRefuseSansMaterielTLS(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Transport.Certificat = ""
	inst.Transport.Cle = ""
	if _, err := Nouveau(inst, ""); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("refus attendu sans matériel TLS, obtenu %v", err)
	}
}

func TestNouveauRefuseMaterielIllisible(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Transport.Certificat = filepath.Join(t.TempDir(), "absent.pem")
	if _, err := Nouveau(inst, ""); err == nil {
		t.Fatal("refus attendu pour un certificat illisible")
	}
}

func TestNouveauRefuseSansAdresse(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Ecoute = ""
	if _, err := Nouveau(inst, ""); err == nil || !strings.Contains(err.Error(), "écoute") {
		t.Fatalf("refus attendu sans adresse d'écoute, obtenu %v", err)
	}
}

func TestServirTLSEtArretPropre(t *testing.T) {
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)

	// La surcharge --ecoute l'emporte sur instance.ecoute.
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

	pemAC, err := os.ReadFile(cheminCertificat)
	if err != nil {
		t.Fatal(err)
	}
	magasin := x509.NewCertPool()
	if !magasin.AppendCertsFromPEM(pemAC) {
		t.Fatal("certificat de test inexploitable")
	}
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: magasin, MinVersion: tls.VersionTLS12}},
	}
	reponse, err := client.Get("https://" + serveur.Adresse() + "/v1/politique")
	if err != nil {
		t.Fatal(err)
	}
	defer reponse.Body.Close()
	if reponse.StatusCode != http.StatusOK {
		t.Fatalf("statut = %d", reponse.StatusCode)
	}
	if reponse.TLS == nil || reponse.TLS.Version != tls.VersionTLS13 {
		t.Errorf("TLS 1.3 attendu (version_min = 1.3), obtenu %+v", reponse.TLS)
	}
	var politique config.Politique
	if err := json.NewDecoder(reponse.Body).Decode(&politique); err != nil {
		t.Fatal(err)
	}
	if politique.Instance != "ardoise-test" {
		t.Errorf("politique inattendue : %+v", politique)
	}

	annuler()
	select {
	case err := <-termine:
		if err != nil {
			t.Fatalf("arrêt propre attendu, obtenu %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("le serveur ne s'est pas arrêté")
	}
}

func TestSuitesTLS12SansFaiblesse(t *testing.T) {
	for _, suite := range SuitesTLS12() {
		nom := tls.CipherSuiteName(suite)
		if !strings.HasPrefix(nom, "TLS_ECDHE_") {
			t.Errorf("suite sans ECDHE : %s", nom)
		}
		if strings.Contains(nom, "CBC") || strings.Contains(nom, "RC4") || strings.Contains(nom, "3DES") {
			t.Errorf("suite faible : %s", nom)
		}
	}
}
