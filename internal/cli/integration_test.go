package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
	"ardoise.pm/internal/store"
)

// instanceIntegration construit une configuration d'instance valide pour
// les tests de bout en bout ; muter ajuste les réglages du cas.
func instanceIntegration(t *testing.T, muter func(map[string]map[string]any)) *config.Instance {
	t.Helper()
	m := map[string]map[string]any{
		"instance": {"nom": "ardoise-integration", "mode": "aveugle", "ecoute": "127.0.0.1:0"},
		// Le chemin auth.jetons n'est pas résolu ici : la table est fournie
		// à server.Handler par serveurIntegration (Nouveau seul lit le fichier).
		"auth":      {"mecanisme": "jeton", "jetons": "/etc/ardoise/jetons.json"},
		"contenu":   {"chiffrement": "cle", "taille_max": "64Kio"},
		"retention": {"support": "memoire", "lecture_unique": "au-choix", "duree_max": "24h", "duree_defaut": "1h"},
		"transport": {"certificat": "/tmp/inutilise.pem", "cle": "/tmp/inutilise.key"},
		"marquage":  {"actif": true, "libelle": "DIFFUSION RESTREINTE"},
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

// jetonIntegration est le jeton AUTH-3 des tests de bout en bout.
const jetonIntegration = "jeton-integration-tres-secret"

// serveurIntegration expose le Handler complet derrière TLS et retourne
// l'environnement client : endpoint, AC de confiance et, pour une instance
// à jeton, le fichier de jeton (ARDOISE_JETON).
func serveurIntegration(t *testing.T, inst *config.Instance, magasin store.Magasin) map[string]string {
	t.Helper()
	return serveurIntegrationAvec(t, inst, magasin, server.Dependances{})
}

// serveurIntegrationAvec est la variante à collaborateurs explicites
// (analyseur ICAP, journal) pour les tests du mode analysé.
func serveurIntegrationAvec(t *testing.T, inst *config.Instance, magasin store.Magasin, deps server.Dependances) map[string]string {
	t.Helper()
	env := map[string]string{}
	var jetons *server.Jetons
	if inst.Auth.Mecanisme == config.MecanismeJeton {
		empreinte := sha256.Sum256([]byte(jetonIntegration))
		table := fmt.Sprintf(`{"alice.durand": %q}`, hex.EncodeToString(empreinte[:]))
		var err error
		if jetons, err = server.AnalyserJetons([]byte(table)); err != nil {
			t.Fatal(err)
		}
		cheminJeton := filepath.Join(t.TempDir(), "jeton")
		if err := os.WriteFile(cheminJeton, []byte(jetonIntegration+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env["ARDOISE_JETON"] = cheminJeton
	}
	ts := httptest.NewTLSServer(server.Handler(inst, magasin, jetons, deps))
	t.Cleanup(ts.Close)
	cheminAC := filepath.Join(t.TempDir(), "ac.pem")
	pemAC := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(cheminAC, pemAC, 0o600); err != nil {
		t.Fatal(err)
	}
	env["ARDOISE_ENDPOINT"] = ts.URL
	env["ARDOISE_AC"] = cheminAC
	return env
}

func magasinMemoire(t *testing.T) store.Magasin {
	t.Helper()
	magasin := store.NouveauMemoire(context.Background(), time.Hour)
	t.Cleanup(func() { magasin.Fermer() })
	return magasin
}

func avecStdin(contenu string) func(*Contexte) {
	return func(ctx *Contexte) {
		ctx.Stdin = strings.NewReader(contenu)
		ctx.StdinTTY = false
	}
}

func avecMotDePasse(motDePasse string) func(*Contexte) {
	return func(ctx *Contexte) {
		ctx.LireMotDePasse = func(string) ([]byte, error) {
			return []byte(motDePasse), nil
		}
	}
}

// pousser exécute un push et retourne l'identifiant émis sur stdout.
func pousser(t *testing.T, env map[string]string, contenu string, options []string, extra ...func(*Contexte)) resultat {
	t.Helper()
	args := append([]string{"push"}, options...)
	opts := append([]func(*Contexte){avecEnvironnement(env), avecStdin(contenu)}, extra...)
	return executer(t, args, opts...)
}

// enTeteMarquageIntegration est la ligne MARQ-1 que « get » place en tête
// de toute restitution des instances de test (marquage actif, libellé
// « DIFFUSION RESTREINTE », internal/marquage).
const enTeteMarquageIntegration = "=== DIFFUSION RESTREINTE ===\n"

func identifiantDe(t *testing.T, r resultat) string {
	t.Helper()
	if r.code != CodeOK {
		t.Fatalf("push : code = %d (stderr : %s)", r.code, r.stderr)
	}
	identifiant := strings.TrimSpace(r.stdout)
	if identifiant == "" {
		t.Fatal("aucun identifiant sur la sortie standard")
	}
	return identifiant
}

func TestIntegrationCHIF2(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	contenu := "extrait de journal\nligne 2\n"

	r := pousser(t, env, contenu, []string{"-t", "2h"})
	identifiant := identifiantDe(t, r)
	if !strings.Contains(identifiant, "#") {
		t.Fatalf("identifiant CHIF-2 sans fragment de clé : %q", identifiant)
	}
	// Affichage avant envoi (docs/man.md, EXEMPLES) sur la sortie d'erreur.
	for _, motif := range []string{
		"Instance : ardoise-integration (mode aveugle, chiffrement local)",
		"Marquage : DIFFUSION RESTREINTE",
		"Durée    : 2h",
	} {
		if !strings.Contains(r.stderr, motif) {
			t.Errorf("bannière : motif %q absent de :\n%s", motif, r.stderr)
		}
	}
	// L'identifiant complet ne fuit jamais sur la sortie d'erreur.
	if strings.Contains(r.stderr, identifiant) {
		t.Error("l'identifiant complet apparaît sur la sortie d'erreur")
	}

	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK {
		t.Fatalf("get : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}
	// MARQ-1 : le libellé de l'instance précède le contenu restitué,
	// inchangé par ailleurs (ES-11, internal/marquage).
	if lecture.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("contenu rendu = %q, attendu %q", lecture.stdout, enTeteMarquageIntegration+contenu)
	}
}

func TestIntegrationCHIF3(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["contenu"]["chiffrement"] = "motdepasse"
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	contenu := "protégé par mot de passe seul"

	r := pousser(t, env, contenu, nil, avecMotDePasse("grand-large"))
	identifiant := identifiantDe(t, r)
	if strings.Contains(identifiant, "#") {
		t.Fatalf("identifiant CHIF-3 avec fragment : %q (la clé dérive du mot de passe)", identifiant)
	}

	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env), avecMotDePasse("grand-large"))
	if lecture.code != CodeOK || lecture.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("get : code = %d, stdout = %q (stderr : %s)", lecture.code, lecture.stdout, lecture.stderr)
	}

	mauvais := executer(t, []string{"get", identifiant}, avecEnvironnement(env), avecMotDePasse("erroné"))
	if mauvais.code != CodeErreur || !strings.Contains(mauvais.stderr, "déchiffrement impossible") {
		t.Fatalf("mauvais mot de passe : code = %d, stderr = %q", mauvais.code, mauvais.stderr)
	}
	if mauvais.stdout != "" {
		t.Error("aucun contenu ne doit sortir après un échec de déchiffrement")
	}
}

func TestIntegrationCHIF1(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["contenu"]["chiffrement"] = "cle+motdepasse"
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	contenu := "deux secrets requis pour ouvrir"

	// Le mot de passe est exigé par la politique, même sans « -p ».
	r := pousser(t, env, contenu, nil, avecMotDePasse("cap-horn"))
	identifiant := identifiantDe(t, r)
	if !strings.Contains(identifiant, "#") {
		t.Fatalf("identifiant CHIF-1 sans fragment : %q", identifiant)
	}

	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env), avecMotDePasse("cap-horn"))
	if lecture.code != CodeOK || lecture.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("get : code = %d, stdout = %q (stderr : %s)", lecture.code, lecture.stdout, lecture.stderr)
	}

	// Mauvais fragment : identifiant altéré, bon mot de passe.
	id, fragment, _ := strings.Cut(identifiant, "#")
	altere := []byte(fragment)
	if altere[0] == 'A' {
		altere[0] = 'B'
	} else {
		altere[0] = 'A'
	}
	mauvaisFragment := executer(t, []string{"get", id + "#" + string(altere)},
		avecEnvironnement(env), avecMotDePasse("cap-horn"))
	if mauvaisFragment.code != CodeErreur || !strings.Contains(mauvaisFragment.stderr, "déchiffrement impossible") {
		t.Fatalf("mauvais fragment : code = %d, stderr = %q", mauvaisFragment.code, mauvaisFragment.stderr)
	}

	// Bon fragment, mauvais mot de passe.
	mauvaisMotDePasse := executer(t, []string{"get", identifiant},
		avecEnvironnement(env), avecMotDePasse("erroné"))
	if mauvaisMotDePasse.code != CodeErreur {
		t.Fatalf("mauvais mot de passe : code = %d", mauvaisMotDePasse.code)
	}
}

func TestIntegrationLectureUnique(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	r := pousser(t, env, "à lire une seule fois", []string{"-b"})
	identifiant := identifiantDe(t, r)
	if !strings.Contains(r.stderr, "destruction à la première lecture") {
		t.Errorf("bannière sans mention de la lecture unique :\n%s", r.stderr)
	}

	premiere := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if premiere.code != CodeOK || premiere.stdout != enTeteMarquageIntegration+"à lire une seule fois" {
		t.Fatalf("première lecture : code = %d, stdout = %q", premiere.code, premiere.stdout)
	}
	seconde := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if seconde.code != CodeIntrouvable {
		t.Fatalf("seconde lecture : code = %d, attendu %d", seconde.code, CodeIntrouvable)
	}
	if !strings.Contains(seconde.stderr, "ardoise inexistante, expirée ou déjà consommée") {
		t.Errorf("message code 5 attendu :\n%s", seconde.stderr)
	}
}

func TestIntegrationExpiration(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	identifiant := identifiantDe(t, pousser(t, env, "éphémère", []string{"-t", "1s"}))

	time.Sleep(1100 * time.Millisecond)
	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeIntrouvable {
		t.Fatalf("lecture après expiration : code = %d, attendu %d (stderr : %s)",
			lecture.code, CodeIntrouvable, lecture.stderr)
	}
}

func TestIntegrationRefusLocaux(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["retention"]["lecture_unique"] = "interdite"
		m["retention"]["duree_max"] = "1h"
		m["contenu"]["taille_max"] = "1Kio"
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))

	if r := pousser(t, env, "x", []string{"-b"}); r.code != CodeRefusPolitique {
		t.Errorf("-b interdit : code = %d, attendu %d (stderr : %s)", r.code, CodeRefusPolitique, r.stderr)
	}
	if r := pousser(t, env, "x", []string{"-t", "24h"}); r.code != CodeRefusPolitique {
		t.Errorf("durée au-delà de la borne : code = %d, attendu %d", r.code, CodeRefusPolitique)
	}
	if r := pousser(t, env, "x", []string{"-p"}); r.code != CodeRefusPolitique {
		t.Errorf("-p avec CHIF-2 : code = %d, attendu %d (stderr : %s)", r.code, CodeRefusPolitique, r.stderr)
	}
	if r := pousser(t, env, strings.Repeat("a", 2048), nil); r.code != CodeTailleDepassee {
		t.Errorf("taille dépassée : code = %d, attendu %d", r.code, CodeTailleDepassee)
	}
}

func TestIntegrationPushJSONEtVerifierEmpreinte(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	r := pousser(t, env, "sortie structurée", []string{"--json"})
	if r.code != CodeOK {
		t.Fatalf("push --json : code = %d (stderr : %s)", r.code, r.stderr)
	}
	var corps struct {
		Identifiant string `json:"identifiant"`
		ID          string `json:"id"`
		Empreinte   string `json:"empreinte"`
		Echeance    string `json:"echeance"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &corps); err != nil {
		t.Fatalf("JSON illisible : %v\n%s", err, r.stdout)
	}
	if corps.Identifiant == "" || corps.ID == "" || len(corps.Empreinte) != 64 || corps.Echeance == "" {
		t.Fatalf("corps inattendu : %+v", corps)
	}
	if !strings.HasPrefix(corps.Identifiant, corps.ID+"#") {
		t.Errorf("identifiant %q sans rapport avec id %q", corps.Identifiant, corps.ID)
	}

	// « --verifier-empreinte » : la bonne empreinte passe, une autre refuse.
	bonne := executer(t, []string{"get", "--verifier-empreinte", corps.Empreinte, corps.Identifiant}, avecEnvironnement(env))
	if bonne.code != CodeOK {
		t.Fatalf("bonne empreinte refusée : code = %d (stderr : %s)", bonne.code, bonne.stderr)
	}

	identifiant2 := identifiantDe(t, pousser(t, env, "autre contenu", nil))
	mauvaise := executer(t, []string{"get", "--verifier-empreinte", corps.Empreinte, identifiant2}, avecEnvironnement(env))
	if mauvaise.code != CodeErreur || !strings.Contains(mauvaise.stderr, "verifier-empreinte") {
		t.Fatalf("mauvaise empreinte : code = %d, stderr = %q", mauvaise.code, mauvaise.stderr)
	}
	if mauvaise.stdout != "" {
		t.Error("aucun contenu ne doit sortir quand l'empreinte fournie diverge")
	}
}

func TestIntegrationSortieFichierEtIdentifiantSurStdin(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	identifiant := identifiantDe(t, pousser(t, env, "contenu vers fichier", nil))

	chemin := filepath.Join(t.TempDir(), "restitution.txt")
	// « get - » : l'identifiant arrive par l'entrée standard.
	lecture := executer(t, []string{"get", "-o", chemin, "-"},
		avecEnvironnement(env), avecStdin(identifiant+"\n"))
	if lecture.code != CodeOK {
		t.Fatalf("get - : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}
	if lecture.stdout != "" {
		t.Error("rien ne doit sortir sur stdout avec --sortie")
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if string(donnees) != enTeteMarquageIntegration+"contenu vers fichier" {
		t.Fatalf("fichier = %q", donnees)
	}
	infos, err := os.Stat(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if infos.Mode().Perm() != 0o600 {
		t.Errorf("droits du fichier de sortie = %v, attendu 0600", infos.Mode().Perm())
	}
}

func TestIntegrationSilencieux(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	r := pousser(t, env, "sans bavardage", []string{"-q"})
	if r.code != CodeOK {
		t.Fatalf("code = %d", r.code)
	}
	if r.stderr != "" {
		t.Errorf("aucun message attendu avec --silencieux, obtenu :\n%s", r.stderr)
	}
}

// TestIntegrationMagasinDisque rejoue un dépôt/récupération au travers du
// magasin sur disque chiffré, avec redémarrage simulé de l'instance entre
// le dépôt et la lecture (RET-3 : survit au redémarrage).
func TestIntegrationMagasinDisque(t *testing.T) {
	repertoire := t.TempDir()
	cle := make([]byte, 32)
	if _, err := rand.Read(cle); err != nil {
		t.Fatal(err)
	}
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["retention"]["support"] = "disque-chiffre"
		m["retention"]["cle_magasin"] = "/etc/ardoise/inutilise.cle"
		m["retention"]["repertoire"] = repertoire
	})

	premier, err := store.NouveauDisque(context.Background(), repertoire, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	env := serveurIntegration(t, inst, premier)
	identifiant := identifiantDe(t, pousser(t, env, "survivant du redémarrage", nil))
	premier.Fermer()

	// « Redémarrage » : nouveau magasin sur le même répertoire, même clé,
	// nouveau serveur.
	second, err := store.NouveauDisque(context.Background(), repertoire, cle, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Fermer()
	env2 := serveurIntegration(t, inst, second)

	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env2))
	if lecture.code != CodeOK || lecture.stdout != enTeteMarquageIntegration+"survivant du redémarrage" {
		t.Fatalf("lecture après redémarrage : code = %d, stdout = %q (stderr : %s)",
			lecture.code, lecture.stdout, lecture.stderr)
	}
}

// TestIntegrationInjoignable vérifie le code 9 lorsque l'instance ne
// répond pas.
func TestIntegrationInjoignable(t *testing.T) {
	env := map[string]string{"ARDOISE_ENDPOINT": "https://127.0.0.1:1"}
	r := pousser(t, env, "x", nil)
	if r.code != CodeInjoignable {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeInjoignable, r.stderr)
	}
	if !strings.Contains(r.stderr, "injoignable") {
		t.Errorf("message attendu :\n%s", r.stderr)
	}
}

// TestIntegrationEndpointNonHTTPS : aucun flux en clair, jamais.
func TestIntegrationEndpointNonHTTPS(t *testing.T) {
	env := map[string]string{"ARDOISE_ENDPOINT": "http://ardoise.interne:8080"}
	r := pousser(t, env, "x", nil)
	if r.code != CodeUsage || !strings.Contains(r.stderr, "https") {
		t.Fatalf("code = %d, stderr = %q", r.code, r.stderr)
	}
}
