package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serveurFactice monte un endpoint HTTP nu (le TLS de bout en bout est
// couvert par les tests d'intégration d'internal/cli).
func serveurFactice(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &Client{endpoint: ts.URL, http: ts.Client()}
}

func TestErreurAPIDepuisReponse(t *testing.T) {
	c := serveurFactice(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"erreur":{"code":"introuvable","message":"ardoise inexistante, expirée ou déjà consommée"}}`))
	})
	_, err := c.Recuperer("abcdefghij29")
	e, ok := err.(*ErreurAPI)
	if !ok {
		t.Fatalf("erreur = %T (%v), attendu *ErreurAPI", err, err)
	}
	if e.Statut != http.StatusNotFound || e.Code != "introuvable" ||
		!strings.Contains(e.Error(), "ardoise inexistante") {
		t.Fatalf("erreur = %+v", e)
	}
}

func TestErreurAPICorpsIllisible(t *testing.T) {
	c := serveurFactice(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("mandataire fou"))
	})
	_, err := c.Politique()
	e, ok := err.(*ErreurAPI)
	if !ok {
		t.Fatalf("erreur = %T, attendu *ErreurAPI", err)
	}
	if e.Statut != http.StatusBadGateway || !strings.Contains(e.Error(), "502") {
		t.Fatalf("erreur = %+v", e)
	}
}

func TestErreurReseau(t *testing.T) {
	c := Nouveau("https://127.0.0.1:1", nil)
	_, err := c.Politique()
	if _, ok := err.(*ErreurReseau); !ok {
		t.Fatalf("erreur = %T (%v), attendu *ErreurReseau", err, err)
	}
}

func TestDeposerNEnvoieQueLeChiffre(t *testing.T) {
	var corps map[string]any
	c := serveurFactice(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&corps); err != nil {
			t.Errorf("corps illisible : %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"abcdefghij29","empreinte":"00","echeance":"2026-01-01T00:00:00Z"}`))
	})
	chiffre := []byte{0x01, 0x02, 0x03}
	reponse, err := c.Deposer(&Depot{Chiffre: chiffre, Duree: "1h", LectureUnique: true})
	if err != nil {
		t.Fatal(err)
	}
	if reponse.ID != "abcdefghij29" {
		t.Fatalf("réponse = %+v", reponse)
	}
	if corps["contenu"] != base64.StdEncoding.EncodeToString(chiffre) {
		t.Errorf("contenu = %v", corps["contenu"])
	}
	if corps["duree"] != "1h" || corps["lecture_unique"] != true {
		t.Errorf("corps = %v", corps)
	}
	// Aucun autre champ que ceux du contrat : rien qui ressemble à une clé.
	for champ := range corps {
		switch champ {
		case "contenu", "duree", "lecture_unique", "marquage_complement":
		default:
			t.Errorf("champ inattendu dans le dépôt : %q", champ)
		}
	}
}

// serveurAuth simule une instance : politique avec le mécanisme donné,
// dépôt qui enregistre les en-têtes reçus.
func serveurAuth(t *testing.T, mecanisme string) (*Client, *http.Header, *int) {
	t.Helper()
	var entetes http.Header
	appelsPolitique := 0
	c := serveurFactice(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/politique" {
			appelsPolitique++
			w.Write([]byte(`{"instance":"t","mode":"aveugle","identification":"` + mecanisme + `"}`))
			return
		}
		entetes = r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"abcdefghij29","empreinte":"00","echeance":"2026-01-01T00:00:00Z"}`))
	})
	return c, &entetes, &appelsPolitique
}

// TestJetonEnvoyeEnBearer : le jeton fourni part en « Authorization:
// Bearer … », et uniquement là.
func TestJetonEnvoyeEnBearer(t *testing.T) {
	c, entetes, _ := serveurAuth(t, "jeton")
	c.DefinirJeton([]byte("jeton-secret"))
	if _, err := c.Deposer(&Depot{Chiffre: []byte{0x01}}); err != nil {
		t.Fatal(err)
	}
	if obtenu := entetes.Get("Authorization"); obtenu != "Bearer jeton-secret" {
		t.Errorf("Authorization = %q", obtenu)
	}
	if entetes.Get("X-Ardoise-Utilisateur") != "" {
		t.Error("aucun en-tête déclaratif ne doit accompagner un jeton")
	}
}

// TestEntetesDeclaratifsSelonPolitique : l'identité déclarée n'est envoyée
// que si la politique de l'instance retient l'identification déclarative,
// et la politique n'est interrogée qu'une fois (mémorisée).
func TestEntetesDeclaratifsSelonPolitique(t *testing.T) {
	c, entetes, appels := serveurAuth(t, "declaratif")
	c.DeclarerIdentite("alice.durand", "poste-adm-07")
	for i := 0; i < 2; i++ {
		if _, err := c.Deposer(&Depot{Chiffre: []byte{0x01}}); err != nil {
			t.Fatal(err)
		}
	}
	if entetes.Get("X-Ardoise-Utilisateur") != "alice.durand" || entetes.Get("X-Ardoise-Hote") != "poste-adm-07" {
		t.Errorf("en-têtes déclaratifs = %q / %q", entetes.Get("X-Ardoise-Utilisateur"), entetes.Get("X-Ardoise-Hote"))
	}
	if *appels != 1 {
		t.Errorf("politique interrogée %d fois, attendu 1 (mémorisation)", *appels)
	}

	// Instance non déclarative : l'identité déclarée reste sur le poste.
	c2, entetes2, _ := serveurAuth(t, "mtls")
	c2.DeclarerIdentite("alice.durand", "poste-adm-07")
	if _, err := c2.Deposer(&Depot{Chiffre: []byte{0x01}}); err != nil {
		t.Fatal(err)
	}
	if entetes2.Get("X-Ardoise-Utilisateur") != "" || entetes2.Get("X-Ardoise-Hote") != "" {
		t.Error("les en-têtes déclaratifs ne doivent partir que vers une instance déclarative")
	}
}

// TestEstRefusCertificatClient reconnaît les alertes TLS d'une instance
// exigeant un certificat client, sans englober les autres erreurs.
func TestEstRefusCertificatClient(t *testing.T) {
	cas := map[string]bool{
		"remote error: tls: certificate required":           true,
		"remote error: tls: bad certificate":                true,
		"remote error: tls: unknown certificate authority":  true,
		"dial tcp 127.0.0.1:1: connect: connection refused": false,
		"x509: certificate signed by unknown authority":     false,
		"context deadline exceeded":                         false,
	}
	for message, attendu := range cas {
		if obtenu := EstRefusCertificatClient(errors.New(message)); obtenu != attendu {
			t.Errorf("EstRefusCertificatClient(%q) = %v, attendu %v", message, obtenu, attendu)
		}
	}
	if EstRefusCertificatClient(nil) {
		t.Error("nil ne doit pas être un refus de certificat")
	}
}
