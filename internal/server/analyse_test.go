package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/icap"
	"ardoise.pm/internal/icap/icaptest"
	"ardoise.pm/internal/journal"
	"ardoise.pm/internal/store"
)

const jetonAnalyse = "jeton-analyse-tres-secret"

// instanceAnalyse construit une instance en mode analysé : CHIF-4 imposé,
// identification par jeton (l'identification déclarative y est interdite),
// adresse ICAP syntaxiquement valide — jamais contactée, les tests
// injectent leur Analyseur.
func instanceAnalyse(t *testing.T) *config.Instance {
	t.Helper()
	donnees := `{
		"instance":  {"nom": "ardoise-analyse", "mode": "analyse", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": "jeton", "jetons": "/etc/ardoise/jetons.json"},
		"contenu":   {"chiffrement": "serveur", "taille_max": "4Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"analyse":   {"icap_url": "icap://analyse.interne:1344/reqmod", "icap_delai": "2s"},
		"transport": {"certificat": "/tmp/inutilise.pem", "cle": "/tmp/inutilise.key"},
		"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"}
	}`
	inst, problemes, err := config.Analyser([]byte(donnees))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}
	return inst
}

func jetonsAnalyse(t *testing.T) *Jetons {
	t.Helper()
	empreinte := sha256.Sum256([]byte(jetonAnalyse))
	jetons, err := AnalyserJetons(fmt.Appendf(nil, `{"alice.durand": %q}`, hex.EncodeToString(empreinte[:])))
	if err != nil {
		t.Fatal(err)
	}
	return jetons
}

// espionMagasin compte les dépôts qui atteignent le magasin : les refus
// d'analyse ne doivent JAMAIS conserver quoi que ce soit (fail-closed).
type espionMagasin struct {
	store.Magasin
	depots int
}

func (e *espionMagasin) Deposer(a *store.Ardoise) error {
	e.depots++
	return e.Magasin.Deposer(a)
}

func serveurAnalyse(t *testing.T, deps Dependances) (*httptest.Server, *espionMagasin) {
	t.Helper()
	espion := &espionMagasin{Magasin: magasinDeTest(t)}
	serveur := httptest.NewServer(Handler(instanceAnalyse(t), espion, jetonsAnalyse(t), deps))
	t.Cleanup(serveur.Close)
	return serveur, espion
}

// requeteJeton exécute une requête porteuse du jeton AUTH-3 de test.
func requeteJeton(t *testing.T, methode, url, corps string) (*http.Response, []byte) {
	t.Helper()
	var lecteur *strings.Reader
	requete, err := http.NewRequest(methode, url, nil)
	if corps != "" {
		lecteur = strings.NewReader(corps)
		requete, err = http.NewRequest(methode, url, lecteur)
	}
	if err != nil {
		t.Fatal(err)
	}
	if corps != "" {
		requete.Header.Set("Content-Type", "application/json")
	}
	requete.Header.Set("Authorization", "Bearer "+jetonAnalyse)
	reponse, err := http.DefaultClient.Do(requete)
	if err != nil {
		t.Fatal(err)
	}
	defer reponse.Body.Close()
	donnees := make([]byte, 0)
	tampon := make([]byte, 4096)
	for {
		n, errLecture := reponse.Body.Read(tampon)
		donnees = append(donnees, tampon[:n]...)
		if errLecture != nil {
			break
		}
	}
	return reponse, donnees
}

func corpsDepot(t *testing.T, clair []byte) string {
	t.Helper()
	corps, err := json.Marshal(map[string]any{
		"contenu": base64.StdEncoding.EncodeToString(clair),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(corps)
}

// TestAnalyseFavorable : verdict favorable → 201 avec clé CHIF-4 ; le
// magasin ne conserve que du chiffré (version 0x04), la clé retournée
// l'ouvre, et ni le clair ni la clé n'existent ailleurs que dans la
// réponse.
func TestAnalyseFavorable(t *testing.T) {
	analyseur := &icaptest.AnalyseurFixe{Reponse: icap.VerdictFavorable}
	serveur, espion := serveurAnalyse(t, Dependances{Analyseur: analyseur})
	clair := []byte("configuration à faire relire\nligne 2\n")

	reponse, corps := requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises", corpsDepot(t, clair))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d, corps = %s", reponse.StatusCode, corps)
	}
	var depot struct {
		ID        string `json:"id"`
		Empreinte string `json:"empreinte"`
		Echeance  string `json:"echeance"`
		Cle       string `json:"cle"`
	}
	if err := json.Unmarshal(corps, &depot); err != nil {
		t.Fatal(err)
	}
	if !crypto.IDServeurValide(depot.ID) {
		t.Fatalf("identifiant invalide : %q", depot.ID)
	}
	cle, err := base64.RawURLEncoding.DecodeString(depot.Cle)
	if err != nil || len(cle) != crypto.TailleCle {
		t.Fatalf("clé illisible ou de mauvaise taille : %v (%d octets)", err, len(cle))
	}
	// La chaîne d'analyse a vu exactement le clair soumis (ADR-004).
	if string(analyseur.Dernier()) != string(clair) {
		t.Fatalf("contenu soumis à l'analyse = %q, attendu %q", analyseur.Dernier(), clair)
	}

	// Le magasin ne détient que du chiffré CHIF-4 : jamais le clair, jamais
	// la clé.
	conserve, err := espion.Magasin.Recuperer(depot.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version, _ := crypto.Schema(conserve.Chiffre); version != crypto.VersionServeur {
		t.Fatalf("version du chiffré conservé = 0x%02x, attendu 0x%02x", version, crypto.VersionServeur)
	}
	if strings.Contains(string(conserve.Chiffre), string(clair)) {
		t.Fatal("le magasin contient le clair")
	}
	if strings.Contains(string(conserve.Chiffre), string(cle)) || strings.Contains(string(conserve.Chiffre), depot.Cle) {
		t.Fatal("le magasin contient la clé")
	}
	if crypto.Empreinte(conserve.Chiffre) != depot.Empreinte {
		t.Fatal("l'empreinte annoncée ne correspond pas au chiffré conservé")
	}
	// La clé retournée — seule trace existante — ouvre le chiffré.
	rendu, err := crypto.Dechiffrer(conserve.Chiffre, cle)
	if err != nil {
		t.Fatal(err)
	}
	if string(rendu) != string(clair) {
		t.Fatalf("clair rendu = %q, attendu %q", rendu, clair)
	}
}

// TestAnalyseRefus : verdict défavorable, indisponible ou analyseur absent —
// refus 451 avec le code adapté, AUCUNE conservation (fail-closed, ADR-011).
func TestAnalyseRefus(t *testing.T) {
	cas := []struct {
		nom     string
		deps    Dependances
		code    string
		soumis  bool
		verdict icap.Verdict
	}{
		{"verdict défavorable", Dependances{Analyseur: &icaptest.AnalyseurFixe{Reponse: icap.VerdictDefavorable}}, "analyse_defavorable", true, icap.VerdictDefavorable},
		{"verdict indisponible", Dependances{Analyseur: &icaptest.AnalyseurFixe{Reponse: icap.VerdictIndisponible}}, "analyse_indisponible", true, icap.VerdictIndisponible},
		{"analyseur absent", Dependances{}, "analyse_indisponible", false, 0},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			serveur, espion := serveurAnalyse(t, c.deps)
			reponse, corps := requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises",
				corpsDepot(t, []byte("contenu suspect")))
			if reponse.StatusCode != statutAnalyseRefusee {
				t.Fatalf("statut = %d, attendu %d (corps : %s)", reponse.StatusCode, statutAnalyseRefusee, corps)
			}
			if enveloppe := decoderErreurAPI(t, corps); enveloppe.Erreur.Code != c.code {
				t.Fatalf("code = %q, attendu %q", enveloppe.Erreur.Code, c.code)
			}
			if espion.depots != 0 {
				t.Fatal("un refus d'analyse a atteint le magasin (fail-closed violé)")
			}
			if c.soumis {
				if fixe := c.deps.Analyseur.(*icaptest.AnalyseurFixe); fixe.Vus() != 1 {
					t.Fatalf("soumissions = %d, attendu 1 (jamais de réémission)", fixe.Vus())
				}
			}
		})
	}
}

// TestAnalyseTailleMax : la borne s'applique au clair décodé, AVANT toute
// soumission à l'analyse.
func TestAnalyseTailleMax(t *testing.T) {
	analyseur := &icaptest.AnalyseurFixe{Reponse: icap.VerdictFavorable}
	serveur, espion := serveurAnalyse(t, Dependances{Analyseur: analyseur})
	trop := make([]byte, 4097) // taille_max = 4Kio
	reponse, _ := requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises", corpsDepot(t, trop))
	if reponse.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("statut = %d, attendu 413", reponse.StatusCode)
	}
	if analyseur.Vus() != 0 {
		t.Fatal("un contenu hors borne a été soumis à l'analyse")
	}
	if espion.depots != 0 {
		t.Fatal("un contenu hors borne a atteint le magasin")
	}
}

// TestJournalServeur : un cycle complet — dépôt, lecture avec destruction,
// refus d'analyse, refus d'accès — émet exactement les événements attendus,
// chaînés, sans jamais une trace de contenu, de clé ou de fragment.
func TestJournalServeur(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "journal.jsonl")
	jrnl, err := journal.Nouveau(journal.Config{
		Instance:    "ardoise-analyse",
		Niveau:      "DIFFUSION RESTREINTE",
		Destination: "fichier",
		Chainage:    true,
		Fichier:     chemin,
	})
	if err != nil {
		t.Fatal(err)
	}
	ancrage := jrnl.Ancrage()

	analyseur := &icaptest.AnalyseurFixe{Reponse: icap.VerdictFavorable}
	espion := &espionMagasin{Magasin: magasinDeTest(t)}
	// Câblage des destructions vers le journal, comme le fait Nouveau.
	espion.Magasin.(store.NotifiantDestruction).DefinirRappelDestruction(func(id, empreinte, cause string) {
		evenement := journal.EvenementDestructionEcheance
		if cause == store.DestructionLecture {
			evenement = journal.EvenementDestructionLecture
		}
		jrnl.Consigner(journal.Entree{Evenement: evenement, IDServeur: id, Empreinte: empreinte})
	})
	serveur := httptest.NewServer(Handler(instanceAnalyse(t), espion, jetonsAnalyse(t),
		Dependances{Analyseur: analyseur, Journal: jrnl}))
	t.Cleanup(serveur.Close)

	clair := []byte("contenu du cycle journalisé")

	// Dépôt (favorable), à lecture unique.
	corps, _ := json.Marshal(map[string]any{
		"contenu":        base64.StdEncoding.EncodeToString(clair),
		"lecture_unique": true,
	})
	reponse, donnees := requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises", string(corps))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("dépôt : statut = %d (%s)", reponse.StatusCode, donnees)
	}
	var depot struct {
		ID  string `json:"id"`
		Cle string `json:"cle"`
	}
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}

	// Lecture : consomme l'ardoise (destruction_lecture + lecture).
	if reponse, donnees = requeteJeton(t, http.MethodGet, serveur.URL+"/v1/ardoises/"+depot.ID, ""); reponse.StatusCode != http.StatusOK {
		t.Fatalf("lecture : statut = %d (%s)", reponse.StatusCode, donnees)
	}

	// Refus d'analyse.
	analyseur.Reponse = icap.VerdictDefavorable
	if reponse, _ = requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises", corpsDepot(t, []byte("refusé"))); reponse.StatusCode != statutAnalyseRefusee {
		t.Fatalf("refus d'analyse : statut = %d", reponse.StatusCode)
	}

	// Refus d'accès : jeton inconnu.
	requete, _ := http.NewRequest(http.MethodGet, serveur.URL+"/v1/ardoises/"+depot.ID, nil)
	requete.Header.Set("Authorization", "Bearer mauvais-jeton")
	if r, err := http.DefaultClient.Do(requete); err != nil {
		t.Fatal(err)
	} else {
		r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("refus d'accès : statut = %d", r.StatusCode)
		}
	}

	if err := jrnl.Fermer(); err != nil {
		t.Fatal(err)
	}
	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}

	// Rien de secret dans le journal (ADR-005) : ni clair, ni clé, ni
	// fragment, ni même le caractère « # » d'un identifiant complet.
	for _, interdit := range []string{string(clair), depot.Cle, "#", jetonAnalyse, "refusé"} {
		if strings.Contains(string(brut), interdit) {
			t.Errorf("le journal contient %q", interdit)
		}
	}

	var lignes [][]byte
	for _, l := range strings.Split(strings.TrimSpace(string(brut)), "\n") {
		lignes = append(lignes, []byte(l))
	}
	var evenements []string
	for _, l := range lignes {
		var e journal.Entree
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatal(err)
		}
		evenements = append(evenements, e.Evenement)
		switch e.Evenement {
		case journal.EvenementDepot, journal.EvenementLecture:
			if e.Identite == nil || e.Identite.Utilisateur != "alice.durand" ||
				e.Identite.Mecanisme != MecanismeJeton || e.Identite.Declaratif {
				t.Errorf("%s : identité inattendue %+v", e.Evenement, e.Identite)
			}
			if e.IDServeur != depot.ID || e.Empreinte == "" {
				t.Errorf("%s : id/empreinte manquants : %+v", e.Evenement, e)
			}
		case journal.EvenementDepotRefuseAnalyse:
			if e.Identite == nil || e.Identite.Utilisateur != "alice.durand" {
				t.Errorf("refus d'analyse : identité inattendue %+v", e.Identite)
			}
			if e.IDServeur != "" || e.Empreinte != "" {
				t.Errorf("refus d'analyse : aucun id ni empreinte attendus (rien n'est conservé) : %+v", e)
			}
		case journal.EvenementAccesRefuse:
			if e.Identite == nil || e.Identite.Utilisateur != "" || e.Identite.Mecanisme != MecanismeJeton {
				t.Errorf("accès refusé : identité inattendue %+v", e.Identite)
			}
		}
	}
	attendus := []string{
		journal.EvenementDepot,
		journal.EvenementDestructionLecture,
		journal.EvenementLecture,
		journal.EvenementDepotRefuseAnalyse,
		journal.EvenementAccesRefuse,
	}
	if strings.Join(evenements, ",") != strings.Join(attendus, ",") {
		t.Fatalf("événements = %v, attendu %v", evenements, attendus)
	}

	// La chaîne émise est intègre de bout en bout (JOURN-1).
	if i, err := VerifierChaineTest(ancrage, lignes); err != nil || i != -1 {
		t.Fatalf("chaîne : rupture à %d (err %v)", i, err)
	}
}

// VerifierChaineTest délègue à journal.VerifierChaine (indirection locale
// pour garder l'import explicite au point d'usage).
func VerifierChaineTest(ancrage []byte, lignes [][]byte) (int, error) {
	return journal.VerifierChaine(ancrage, lignes)
}

// TestAnalyseCleNonPersistee : sur un magasin disque (RET-3), les octets
// écrits ne contiennent NI le clair NI la clé — la réponse de dépôt est le
// seul endroit où la clé existe (A.3-1, cécité a posteriori).
func TestAnalyseCleNonPersistee(t *testing.T) {
	repertoire := t.TempDir()
	cleMagasin := make([]byte, 32)
	for i := range cleMagasin {
		cleMagasin[i] = byte(i)
	}
	magasin, err := store.NouveauDisque(t.Context(), repertoire, cleMagasin, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { magasin.Fermer() })
	serveur := httptest.NewServer(Handler(instanceAnalyse(t), magasin, jetonsAnalyse(t),
		Dependances{Analyseur: &icaptest.AnalyseurFixe{Reponse: icap.VerdictFavorable}}))
	t.Cleanup(serveur.Close)

	clair := []byte("clair-qui-ne-doit-jamais-toucher-le-disque")
	reponse, corps := requeteJeton(t, http.MethodPost, serveur.URL+"/v1/ardoises", corpsDepot(t, clair))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d (%s)", reponse.StatusCode, corps)
	}
	var depot struct {
		Cle string `json:"cle"`
	}
	if err := json.Unmarshal(corps, &depot); err != nil {
		t.Fatal(err)
	}
	cle, err := base64.RawURLEncoding.DecodeString(depot.Cle)
	if err != nil {
		t.Fatal(err)
	}

	entrees, err := os.ReadDir(repertoire)
	if err != nil {
		t.Fatal(err)
	}
	if len(entrees) == 0 {
		t.Fatal("aucun fichier écrit par le magasin disque")
	}
	for _, entree := range entrees {
		donnees, err := os.ReadFile(filepath.Join(repertoire, entree.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(donnees), string(clair)) {
			t.Fatalf("%s contient le clair", entree.Name())
		}
		if strings.Contains(string(donnees), string(cle)) || strings.Contains(string(donnees), depot.Cle) {
			t.Fatalf("%s contient la clé", entree.Name())
		}
	}
}

// TestNouveauServirAnalyse : démarrage complet d'une instance analysée par
// Nouveau/Servir — montage du journal (fichier), du client ICAP (maquette
// réelle) et du rappel de destruction — puis un dépôt favorable de bout en
// bout et l'arrêt propre, journal drainé.
func TestNouveauServirAnalyse(t *testing.T) {
	maquette, err := icap.DemarrerMaquette(icap.MaquetteFavorable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maquette.Fermer)

	cheminCertificat, cheminCle := genererMaterielTLS(t)
	empreinte := sha256.Sum256([]byte(jetonAnalyse))
	cheminJetons := filepath.Join(t.TempDir(), "jetons.json")
	if err := os.WriteFile(cheminJetons,
		fmt.Appendf(nil, `{"alice.durand": %q}`, hex.EncodeToString(empreinte[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	cheminJournal := filepath.Join(t.TempDir(), "journal.jsonl")

	donnees := fmt.Sprintf(`{
		"instance":  {"nom": "ardoise-analyse", "mode": "analyse", "ecoute": "127.0.0.1:0"},
		"auth":      {"mecanisme": "jeton", "jetons": %q},
		"contenu":   {"chiffrement": "serveur", "taille_max": "4Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"analyse":   {"icap_url": %q, "icap_delai": "2s"},
		"journal":   {"destination": "fichier", "fichier": %q, "chainage": false},
		"transport": {"certificat": %q, "cle": %q},
		"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"}
	}`, cheminJetons, maquette.URL(), cheminJournal, cheminCertificat, cheminCle)
	inst, problemes, err := config.Analyser([]byte(donnees))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}

	serveur, err := Nouveau(inst, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := serveur.Ecouter(); err != nil {
		t.Fatal(err)
	}
	ctx, arreter := context.WithCancel(t.Context())
	fini := make(chan error, 1)
	go func() { fini <- serveur.Servir(ctx) }()

	// Client TLS de test : confiance envers le certificat de l'instance —
	// jamais d'InsecureSkipVerify.
	pemCert, err := os.ReadFile(cheminCertificat)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemCert) {
		t.Fatal("certificat de test inexploitable")
	}
	clientHTTP := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	clair := []byte("dépôt de bout en bout")
	requete, err := http.NewRequest(http.MethodPost, "https://"+serveur.Adresse()+"/v1/ardoises",
		strings.NewReader(corpsDepot(t, clair)))
	if err != nil {
		t.Fatal(err)
	}
	requete.Header.Set("Content-Type", "application/json")
	requete.Header.Set("Authorization", "Bearer "+jetonAnalyse)
	reponse, err := clientHTTP.Do(requete)
	if err != nil {
		t.Fatal(err)
	}
	corps, err := io.ReadAll(reponse.Body)
	reponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d (%s)", reponse.StatusCode, corps)
	}
	var depot struct {
		ID  string `json:"id"`
		Cle string `json:"cle"`
	}
	if err := json.Unmarshal(corps, &depot); err != nil {
		t.Fatal(err)
	}
	if depot.Cle == "" {
		t.Fatal("réponse de dépôt sans clé CHIF-4")
	}
	if string(maquette.DernierCorps()) != string(clair) {
		t.Fatal("le clair n'a pas atteint la chaîne d'analyse")
	}

	// Arrêt propre : Servir rend la main, le journal est drainé et fermé.
	arreter()
	if err := <-fini; err != nil {
		t.Fatal(err)
	}
	journalBrut, err := os.ReadFile(cheminJournal)
	if err != nil {
		t.Fatal(err)
	}
	var entree journal.Entree
	if err := json.Unmarshal([]byte(strings.SplitN(strings.TrimSpace(string(journalBrut)), "\n", 2)[0]), &entree); err != nil {
		t.Fatalf("journal illisible : %v (%q)", err, journalBrut)
	}
	if entree.Evenement != journal.EvenementDepot || entree.IDServeur != depot.ID {
		t.Fatalf("première entrée inattendue : %+v", entree)
	}
	if strings.Contains(string(journalBrut), depot.Cle) || strings.Contains(string(journalBrut), string(clair)) {
		t.Fatal("le journal contient la clé ou le clair")
	}
}

// TestModeAveugleSansCle : en mode aveugle, la réponse de dépôt ne comporte
// jamais de champ cle.
func TestModeAveugleSansCle(t *testing.T) {
	serveur, _ := serveurDeTest(t, nil)
	chiffre := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	reponse, corps := deposer(t, serveur.URL, fmt.Sprintf(`{"contenu": %q}`, chiffre))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("statut = %d", reponse.StatusCode)
	}
	var champs map[string]any
	if err := json.Unmarshal(corps, &champs); err != nil {
		t.Fatal(err)
	}
	if _, present := champs["cle"]; present {
		t.Fatal("champ « cle » présent dans une réponse de dépôt en mode aveugle")
	}
}
