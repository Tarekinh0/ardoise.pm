package server

import (
	"bytes"
	"crypto/sha256"
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

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/journal"
	"ardoise.pm/internal/store"
)

// jetonsPour sont les jetons des identités des tests de désignation.
var jetonsPour = map[string]string{
	"alice.durand":  "jeton-alice",
	"bruno.marchal": "jeton-bruno",
	"mallory.evein": "jeton-mallory",
}

// serveurPour monte une instance authentifiée par jetons, avec table de
// groupes et journal local optionnels.
func serveurPour(t *testing.T, groupes *Groupes, jrnl *journal.Journal) (*httptest.Server, store.Magasin) {
	t.Helper()
	cheminCertificat, cheminCle := genererMaterielTLS(t)
	inst := instanceDeTest(t, cheminCertificat, cheminCle)
	inst.Auth.Mecanisme = config.MecanismeJeton
	inst.Auth.Jetons = "/chemin/inutilise" // la table est fournie ci-dessous
	table := map[string]string{}
	for identite, jeton := range jetonsPour {
		empreinte := sha256.Sum256([]byte(jeton))
		table[identite] = hex.EncodeToString(empreinte[:])
	}
	donnees, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	jetons, err := AnalyserJetons(donnees)
	if err != nil {
		t.Fatal(err)
	}
	magasin := magasinDeTest(t)
	serveur := httptest.NewServer(Handler(inst, magasin, jetons, Dependances{Groupes: groupes, Journal: jrnl}))
	t.Cleanup(serveur.Close)
	return serveur, magasin
}

// requeteJetonPour exécute une requête authentifiée par le jeton de
// l'identité donnée.
func requeteJetonPour(t *testing.T, identite, methode, url string, corps io.Reader) (*http.Response, []byte) {
	t.Helper()
	requete, err := http.NewRequest(methode, url, corps)
	if err != nil {
		t.Fatal(err)
	}
	if corps != nil {
		requete.Header.Set("Content-Type", "application/json")
	}
	requete.Header.Set("Authorization", "Bearer "+jetonsPour[identite])
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

// deposerPour dépose une ardoise désignant les destinataires donnés et
// retourne son identifiant serveur.
func deposerPour(t *testing.T, url string, pour []string) string {
	t.Helper()
	pourJSON, _ := json.Marshal(pour)
	corps := fmt.Sprintf(`{"contenu": %q, "pour": %s}`,
		base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03}), pourJSON)
	reponse, donnees := requeteJetonPour(t, "alice.durand", http.MethodPost, url+"/v1/ardoises", strings.NewReader(corps))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("dépôt : statut = %d (%s)", reponse.StatusCode, donnees)
	}
	var depot reponseDepot
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}
	return depot.ID
}

func TestPourLectureDestinataireDesigne(t *testing.T) {
	serveur, _ := serveurPour(t, nil, nil)
	id := deposerPour(t, serveur.URL, []string{"bruno.marchal"})
	reponse, donnees := requeteJetonPour(t, "bruno.marchal", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil)
	if reponse.StatusCode != http.StatusOK {
		t.Fatalf("destinataire désigné : statut = %d (%s)", reponse.StatusCode, donnees)
	}
}

func TestPourLectureTiersIndistinguable(t *testing.T) {
	// Un tiers authentifié mais non désigné reçoit une réponse OCTET POUR
	// OCTET identique à celle d'une ardoise inexistante : l'identifiant
	// obtenu par un tiers non désigné est inexploitable et ne révèle même
	// pas l'existence de l'ardoise (docs/man.md, « --pour »).
	serveur, _ := serveurPour(t, nil, nil)
	id := deposerPour(t, serveur.URL, []string{"bruno.marchal"})

	refus, corpsRefus := requeteJetonPour(t, "mallory.evein", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil)
	inexistante, corpsInexistante := requeteJetonPour(t, "mallory.evein", http.MethodGet, serveur.URL+"/v1/ardoises/zzzzzzzz9999", nil)

	if refus.StatusCode != http.StatusNotFound || inexistante.StatusCode != http.StatusNotFound {
		t.Fatalf("statuts : refus = %d, inexistante = %d", refus.StatusCode, inexistante.StatusCode)
	}
	if !bytes.Equal(corpsRefus, corpsInexistante) {
		t.Errorf("corps distincts :\nrefus       : %s\ninexistante : %s", corpsRefus, corpsInexistante)
	}
	if refus.Header.Get("Content-Type") != inexistante.Header.Get("Content-Type") {
		t.Error("Content-Type distincts")
	}

	// Le refus n'a rien consommé : le destinataire lit toujours.
	lecture, _ := requeteJetonPour(t, "bruno.marchal", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil)
	if lecture.StatusCode != http.StatusOK {
		t.Fatalf("après refus d'un tiers, le destinataire lit : statut = %d", lecture.StatusCode)
	}
}

func TestPourLectureUniqueNonConsommeeParUnTiers(t *testing.T) {
	serveur, _ := serveurPour(t, nil, nil)
	corps := fmt.Sprintf(`{"contenu": %q, "pour": ["bruno.marchal"], "lecture_unique": true}`,
		base64.StdEncoding.EncodeToString([]byte{0x01}))
	reponse, donnees := requeteJetonPour(t, "alice.durand", http.MethodPost, serveur.URL+"/v1/ardoises", strings.NewReader(corps))
	if reponse.StatusCode != http.StatusCreated {
		t.Fatalf("dépôt : %d (%s)", reponse.StatusCode, donnees)
	}
	var depot reponseDepot
	if err := json.Unmarshal(donnees, &depot); err != nil {
		t.Fatal(err)
	}
	// Le tiers tente d'abord : refus sans consommation.
	if refus, _ := requeteJetonPour(t, "mallory.evein", http.MethodGet, serveur.URL+"/v1/ardoises/"+depot.ID, nil); refus.StatusCode != http.StatusNotFound {
		t.Fatalf("tiers : statut = %d", refus.StatusCode)
	}
	// Le destinataire obtient ensuite le contenu (une seule fois).
	if lecture, _ := requeteJetonPour(t, "bruno.marchal", http.MethodGet, serveur.URL+"/v1/ardoises/"+depot.ID, nil); lecture.StatusCode != http.StatusOK {
		t.Fatalf("destinataire : statut = %d", lecture.StatusCode)
	}
	if relecture, _ := requeteJetonPour(t, "bruno.marchal", http.MethodGet, serveur.URL+"/v1/ardoises/"+depot.ID, nil); relecture.StatusCode != http.StatusNotFound {
		t.Fatalf("relecture après consommation : statut = %d", relecture.StatusCode)
	}
}

func TestPourGroupe(t *testing.T) {
	groupes, err := AnalyserGroupes([]byte(`{"@equipe-reseau": ["bruno.marchal"]}`))
	if err != nil {
		t.Fatal(err)
	}
	serveur, _ := serveurPour(t, groupes, nil)
	id := deposerPour(t, serveur.URL, []string{"@equipe-reseau"})

	if lecture, _ := requeteJetonPour(t, "bruno.marchal", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil); lecture.StatusCode != http.StatusOK {
		t.Fatalf("membre du groupe : statut = %d", lecture.StatusCode)
	}
	if refus, _ := requeteJetonPour(t, "mallory.evein", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil); refus.StatusCode != http.StatusNotFound {
		t.Fatalf("non-membre : statut = %d", refus.StatusCode)
	}
}

func TestPourGroupeIrresoluble(t *testing.T) {
	// Groupe absent de la table (ou aucune table) : il ne correspond à
	// aucune identité — personne ne lit par ce groupe, jamais un accès
	// élargi. L'émetteur lui-même, non désigné individuellement, est refusé.
	for nom, groupes := range map[string]*Groupes{
		"aucune table":   nil,
		"table sans lui": func() *Groupes { g, _ := AnalyserGroupes([]byte(`{"@autre": ["bruno.marchal"]}`)); return g }(),
	} {
		t.Run(nom, func(t *testing.T) {
			serveur, _ := serveurPour(t, groupes, nil)
			id := deposerPour(t, serveur.URL, []string{"@equipe-reseau"})
			for identite := range jetonsPour {
				if reponse, _ := requeteJetonPour(t, identite, http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil); reponse.StatusCode != http.StatusNotFound {
					t.Errorf("%s : statut = %d, attendu 404", identite, reponse.StatusCode)
				}
			}
		})
	}
}

func TestPourJournalLectureRefusee(t *testing.T) {
	cheminJournal := filepath.Join(t.TempDir(), "journal.ndjson")
	jrnl, err := journal.Nouveau(journal.Config{
		Instance:    "ardoise-test",
		Destination: "fichier",
		Fichier:     cheminJournal,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveur, _ := serveurPour(t, nil, jrnl)
	id := deposerPour(t, serveur.URL, []string{"bruno.marchal"})
	if refus, _ := requeteJetonPour(t, "mallory.evein", http.MethodGet, serveur.URL+"/v1/ardoises/"+id, nil); refus.StatusCode != http.StatusNotFound {
		t.Fatalf("tiers : statut = %d", refus.StatusCode)
	}
	if err := jrnl.Fermer(); err != nil {
		t.Fatal(err)
	}
	donnees, err := os.ReadFile(cheminJournal)
	if err != nil {
		t.Fatal(err)
	}
	trouvee := false
	for _, ligne := range strings.Split(strings.TrimSpace(string(donnees)), "\n") {
		var entree journal.Entree
		if err := json.Unmarshal([]byte(ligne), &entree); err != nil {
			t.Fatalf("entrée illisible : %v", err)
		}
		if entree.Evenement == journal.EvenementLectureRefuseeDestinataire {
			trouvee = true
			if entree.IDServeur != id {
				t.Errorf("id_serveur = %q, attendu %q", entree.IDServeur, id)
			}
			if entree.Identite == nil || entree.Identite.Utilisateur != "mallory.evein" {
				t.Errorf("identité consignée : %+v", entree.Identite)
			}
		}
	}
	if !trouvee {
		t.Error("aucun événement lecture_refusee_destinataire dans le journal")
	}
}

func TestAnalyserGroupesInvalides(t *testing.T) {
	cas := map[string]string{
		"nom sans arobase": `{"equipe": ["alice.durand"]}`,
		"membre invalide":  `{"@equipe": ["Alice Durand"]}`,
		"JSON illisible":   `{`,
		"contenu excédent": `{"@equipe": []} {}`,
	}
	for nom, donnees := range cas {
		t.Run(nom, func(t *testing.T) {
			if _, err := AnalyserGroupes([]byte(donnees)); err == nil {
				t.Error("erreur attendue")
			}
		})
	}
}
