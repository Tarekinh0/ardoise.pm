package icap

import (
	"net"
	"testing"
	"time"
)

func clientVers(t *testing.T, m *Maquette, delai time.Duration, regles string) *Client {
	t.Helper()
	c, err := NouveauClient(m.URL(), delai, regles)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestVerdicts éprouve la correspondance complète des verdicts (commentaire
// de paquet) : chaque scénario de la maquette doit produire le verdict
// attendu, et tout ce qui n'est pas un 204 ou un 200 identique doit
// aboutir à un refus (fail-closed, ADR-011).
func TestVerdicts(t *testing.T) {
	cas := []struct {
		nom          string
		comportement Comportement
		attendu      Verdict
	}{
		{"204 favorable", MaquetteFavorable, VerdictFavorable},
		{"200 corps identique favorable", MaquetteEcho, VerdictFavorable},
		{"200 réponse de blocage", MaquetteBlocage, VerdictDefavorable},
		{"200 corps modifié", MaquetteModifie, VerdictDefavorable},
		{"statut d'erreur ICAP", MaquetteErreur, VerdictDefavorable},
		{"réponse malformée", MaquetteCharabia, VerdictIndisponible},
		{"connexion coupée", MaquetteCoupure, VerdictIndisponible},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m, err := DemarrerMaquette(c.comportement)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Fermer()
			verdict := clientVers(t, m, 5*time.Second, "").Analyser([]byte("contenu à analyser"))
			if verdict != c.attendu {
				t.Fatalf("verdict = %v, attendu %v", verdict, c.attendu)
			}
		})
	}
}

// TestVerdictDelaiDepasse : un service muet ne retient jamais le dépôt
// au-delà de analyse.icap_delai — verdict indisponible (fail-closed).
func TestVerdictDelaiDepasse(t *testing.T) {
	m, err := DemarrerMaquette(MaquetteMuette)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Fermer()
	depart := time.Now()
	verdict := clientVers(t, m, 300*time.Millisecond, "").Analyser([]byte("x"))
	if verdict != VerdictIndisponible {
		t.Fatalf("verdict = %v, attendu indisponible", verdict)
	}
	if ecoule := time.Since(depart); ecoule > 3*time.Second {
		t.Fatalf("l'échéance n'a pas borné la soumission (%v)", ecoule)
	}
}

// TestVerdictInjoignable : aucune écoute sur le port — indisponible.
func TestVerdictInjoignable(t *testing.T) {
	// Une écoute ouverte puis refermée garantit un port sans service.
	ecouteur, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adresse := ecouteur.Addr().String()
	ecouteur.Close()
	c, err := NouveauClient("icap://"+adresse+"/analyse", time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if verdict := c.Analyser([]byte("x")); verdict != VerdictIndisponible {
		t.Fatalf("verdict = %v, attendu indisponible", verdict)
	}
}

// TestSoumissionREQMOD : la maquette reçoit le contenu intégral et
// l'en-tête X-Ardoise-Regles lorsque des règles sont configurées (ANA-1).
func TestSoumissionREQMOD(t *testing.T) {
	m, err := DemarrerMaquette(MaquetteFavorable)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Fermer()
	contenu := []byte("extrait de journal\navec plusieurs lignes\n")
	verdict := clientVers(t, m, 5*time.Second, "jeu-de-regles-entite").Analyser(contenu)
	if verdict != VerdictFavorable {
		t.Fatalf("verdict = %v", verdict)
	}
	if string(m.DernierCorps()) != string(contenu) {
		t.Fatalf("corps reçu = %q, attendu %q", m.DernierCorps(), contenu)
	}
	entetes := m.DernierEntetes()
	if entetes["x-ardoise-regles"] != "jeu-de-regles-entite" {
		t.Fatalf("X-Ardoise-Regles = %q", entetes["x-ardoise-regles"])
	}
	if entetes["allow"] != "204" {
		t.Fatalf("Allow = %q, attendu 204", entetes["allow"])
	}
}

// TestSansRegles : sans analyse.icap_regles, aucun en-tête X-Ardoise-Regles
// ne part.
func TestSansRegles(t *testing.T) {
	m, err := DemarrerMaquette(MaquetteFavorable)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Fermer()
	if v := clientVers(t, m, 5*time.Second, "").Analyser([]byte("x")); v != VerdictFavorable {
		t.Fatalf("verdict = %v", v)
	}
	if _, present := m.DernierEntetes()["x-ardoise-regles"]; present {
		t.Fatal("X-Ardoise-Regles émis sans règles configurées")
	}
}

// TestICAPReglesRejet verifie que les caracteres de controle CR/LF dans
// icap_regles sont rejetes a l'emission (pas de transformation silencieuse),
// conformement a DPO-B-003 : toute presence de \r ou \n provoque un verdict
// VerdictIndisponible (fail-closed, ADR-011).
func TestICAPReglesRejet(t *testing.T) {
	cas := []struct {
		nom    string
		regles string
		rejete bool // true si VerdictIndisponible attendu
	}{
		{"valeur normale", "jeu-de-regles-entite", false},
		{"avec CRLF", "foo\r\nInjected-Header: evil", true},
		{"avec LF seul", "foo\nbar", true},
		{"avec CR seul", "foo\rbar", true},
		{"avec multiples CRLF", "test\r\n\r\nSMUGGLED", true},
		{"chaine vide", "", false},
		{"sans CRLF", "regles-normales-sans-retour", false},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m, err := DemarrerMaquette(MaquetteFavorable)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Fermer()

			cl := clientVers(t, m, 5*time.Second, c.regles)
			verdict := cl.Analyser([]byte("contenu a analyser"))

			if c.rejete && verdict != VerdictIndisponible {
				t.Fatalf("verdict = %v, attendu VerdictIndisponible (rejet CR/LF)", verdict)
			}
			if !c.rejete && verdict != VerdictFavorable {
				t.Fatalf("verdict = %v, attendu VerdictFavorable pour regles=%q", verdict, c.regles)
			}
		})
	}
}

// TestICAPReglesInjectionEmission verifie que le client ICAP rejette
// (VerdictIndisponible) les regles contenant des CR/LF, conformement a
// DPO-B-003 (rejet, pas transformation silencieuse).
func TestICAPReglesInjectionEmission(t *testing.T) {
	m, err := DemarrerMaquette(MaquetteFavorable)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Fermer()

	// Des regles avec CRLF doivent provoquer un rejet fail-closed.
	reglesInjection := "regle1\r\nX-Injected: true\r\nregle2"
	verdict := clientVers(t, m, 5*time.Second, reglesInjection).Analyser([]byte("contenu test"))
	if verdict != VerdictIndisponible {
		t.Fatalf("verdict = %v, attendu VerdictIndisponible (rejet CR/LF)", verdict)
	}

	// Verification : sans CRLF, l'en-tete X-Ardoise-Regles est bien emis.
	reglesNormales := "regle1 regle2"
	m2, err := DemarrerMaquette(MaquetteFavorable)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Fermer()
	verdict2 := clientVers(t, m2, 5*time.Second, reglesNormales).Analyser([]byte("contenu test"))
	if verdict2 != VerdictFavorable {
		t.Fatalf("verdict = %v, attendu VerdictFavorable", verdict2)
	}
	entetes := m2.DernierEntetes()
	if entetes["x-ardoise-regles"] != reglesNormales {
		t.Fatalf("X-Ardoise-Regles = %q, attendu %q", entetes["x-ardoise-regles"], reglesNormales)
	}
}

// TestNouveauClient : validation des adresses et du délai.
func TestNouveauClient(t *testing.T) {
	cas := []struct {
		nom     string
		url     string
		delai   time.Duration
		valide  bool
		adresse string
	}{
		{"nominal", "icap://analyse.interne:1344/reqmod", time.Second, true, "analyse.interne:1344"},
		{"port par défaut", "icap://analyse.interne/reqmod", time.Second, true, "analyse.interne:1344"},
		{"schéma inconnu", "http://analyse.interne/reqmod", time.Second, false, ""},
		{"sans hôte", "icap:///reqmod", time.Second, false, ""},
		{"délai nul", "icap://analyse.interne:1344/reqmod", 0, false, ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			client, err := NouveauClient(c.url, c.delai, "")
			if c.valide != (err == nil) {
				t.Fatalf("err = %v, validité attendue %v", err, c.valide)
			}
			if c.valide && client.adresse != c.adresse {
				t.Fatalf("adresse = %q, attendu %q", client.adresse, c.adresse)
			}
		})
	}
}
