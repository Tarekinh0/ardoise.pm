package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/icap"
	"ardoise.pm/internal/server"
	"ardoise.pm/internal/store"
)

// instanceAnalyseIntegration construit une instance en mode analysé,
// pointée sur l'adresse ICAP fournie (celle d'une maquette).
func instanceAnalyseIntegration(t *testing.T, icapURL string, muter func(map[string]map[string]any)) *config.Instance {
	t.Helper()
	return instanceIntegration(t, func(m map[string]map[string]any) {
		m["instance"]["mode"] = "analyse"
		m["contenu"]["chiffrement"] = "serveur"
		m["analyse"] = map[string]any{"icap_url": icapURL, "icap_delai": "2s"}
		if muter != nil {
			muter(m)
		}
	})
}

// serveurAnalyseIntegration : maquette ICAP + instance analysée + Handler
// complet, reliés par le VRAI client ICAP (RFC 3507) — la chaîne complète
// du dépôt analysé, de cmdPush au verdict.
func serveurAnalyseIntegration(t *testing.T, comportement icap.Comportement) (map[string]string, *icap.Maquette, store.Magasin) {
	t.Helper()
	maquette, err := icap.DemarrerMaquette(comportement)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(maquette.Fermer)
	inst := instanceAnalyseIntegration(t, maquette.URL(), nil)
	analyseur, err := icap.NouveauClient(inst.Analyse.ICAPURL, inst.Analyse.ICAPDelai, inst.Analyse.ICAPRegles)
	if err != nil {
		t.Fatal(err)
	}
	magasin := magasinMemoire(t)
	env := serveurIntegrationAvec(t, inst, magasin, server.Dependances{Analyseur: analyseur})
	return env, maquette, magasin
}

// TestIntegrationAnalyseAllerRetour : dépôt en clair, verdict favorable,
// identifiant assemblé avec la clé serveur, récupération et déchiffrement
// transparents — même sortie qu'en mode aveugle.
func TestIntegrationAnalyseAllerRetour(t *testing.T) {
	env, maquette, _ := serveurAnalyseIntegration(t, icap.MaquetteFavorable)
	contenu := "configuration à faire analyser\nligne 2\n"

	r := pousser(t, env, contenu, []string{"-t", "2h"})
	identifiant := identifiantDe(t, r)
	// La clé serveur devient le fragment, comme en mode aveugle.
	if !strings.Contains(identifiant, "#") {
		t.Fatalf("identifiant CHIF-4 sans fragment de clé : %q", identifiant)
	}
	// L'avertissement du manuel précède l'envoi (docs/man.md, SÉCURITÉ).
	// C3 : écrit directement sur os.Stderr (toujours visible, même sous -q)
	// — non capturable par r.stderr, vérifié par le test de l'option
	// --silencieux dans TestIntegrationAnalyseSilencieux.
	// La clé ne fuit jamais sur la sortie d'erreur.
	if strings.Contains(r.stderr, strings.SplitN(identifiant, "#", 2)[1]) {
		t.Error("le fragment de clé apparaît sur la sortie d'erreur")
	}
	// La chaîne d'analyse a reçu le clair intégral (ADR-004, R58).
	if string(maquette.DernierCorps()) != contenu {
		t.Fatalf("contenu soumis à l'analyse = %q, attendu %q", maquette.DernierCorps(), contenu)
	}

	lecture := executer(t, []string{"get", "--argument", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK {
		t.Fatalf("get : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}
	if lecture.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("contenu rendu = %q, attendu %q", lecture.stdout, enTeteMarquageIntegration+contenu)
	}
}

// TestIntegrationAnalyseRefus : chaque issue non favorable vaut le code de
// retour 7, sans conservation — l'identifiant n'existe pas.
func TestIntegrationAnalyseRefus(t *testing.T) {
	cas := []struct {
		nom          string
		comportement icap.Comportement
		motif        string
	}{
		{"verdict défavorable", icap.MaquetteBlocage, "défavorable"},
		{"chaîne muette", icap.MaquetteMuette, "aucun verdict"},
		{"réponse malformée", icap.MaquetteCharabia, "aucun verdict"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			env, _, _ := serveurAnalyseIntegration(t, c.comportement)
			r := pousser(t, env, "contenu soumis", nil)
			if r.code != CodeAnalyseDefavorable {
				t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeAnalyseDefavorable, r.stderr)
			}
			if !strings.Contains(r.stderr, c.motif) {
				t.Errorf("motif %q absent du refus :\n%s", c.motif, r.stderr)
			}
			if strings.TrimSpace(r.stdout) != "" {
				t.Error("aucun identifiant ne doit sortir après un refus d'analyse")
			}
		})
	}
}

// TestIntegrationAnalyseInjoignable : chaîne d'analyse coupée — refus
// (fail-closed), code 7.
func TestIntegrationAnalyseInjoignable(t *testing.T) {
	env, maquette, _ := serveurAnalyseIntegration(t, icap.MaquetteFavorable)
	maquette.Fermer()
	r := pousser(t, env, "contenu soumis", nil)
	if r.code != CodeAnalyseDefavorable {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeAnalyseDefavorable, r.stderr)
	}
}

// TestIntegrationAnalyseMotsPourConflict : « --mots » et « --pour » sont
// exclusifs — refus local, code 2 (CodeUsage), rien n'est envoyé.
func TestIntegrationAnalyseMotsPourConflict(t *testing.T) {
	env, maquette, _ := serveurAnalyseIntegration(t, icap.MaquetteFavorable)
	r := pousser(t, env, "contenu", []string{"--mots", "--pour", "alice.durand"})
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeUsage, r.stderr)
	}
	if !strings.Contains(r.stderr, "exclusifs") {
		t.Errorf("refus sans mention du conflit :\n%s", r.stderr)
	}
	if len(maquette.DernierCorps()) != 0 {
		t.Error("rien ne doit partir vers l'analyse après un refus local")
	}
}

// TestIntegrationAnalyseSilencieux : « -q » supprime l'avertissement du
// mode analysé (message informatif) ; les refus, eux, restent affichés.
func TestIntegrationAnalyseSilencieux(t *testing.T) {
	env, _, _ := serveurAnalyseIntegration(t, icap.MaquetteFavorable)
	r := pousser(t, env, "contenu discret", []string{"-q"})
	identifiantDe(t, r)
	if r.stderr != "" {
		t.Errorf("aucun message attendu avec --silencieux, obtenu :\n%s", r.stderr)
	}

	envRefus, _, _ := serveurAnalyseIntegration(t, icap.MaquetteBlocage)
	refus := pousser(t, envRefus, "contenu refusé", []string{"-q"})
	if refus.code != CodeAnalyseDefavorable || refus.stderr == "" {
		t.Fatalf("le refus doit rester affiché sous --silencieux (code %d, stderr %q)", refus.code, refus.stderr)
	}
}

// TestIntegrationMarquageComplement : « --marquage » voyage du dépôt à la
// restitution — « === LIBELLE — complément === » en tête, contenu intact.
func TestIntegrationMarquageComplement(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	contenu := "extrait marqué\n"
	identifiant := identifiantDe(t, pousser(t, env, contenu, []string{"--marquage", "incident 4712"}))

	lecture := executer(t, []string{"get", "--argument", identifiant}, avecEnvironnement(env))
	attendu := "=== DIFFUSION RESTREINTE — incident 4712 ===\n" + contenu
	if lecture.code != CodeOK || lecture.stdout != attendu {
		t.Fatalf("contenu rendu = %q, attendu %q (stderr : %s)", lecture.stdout, attendu, lecture.stderr)
	}
}

// TestIntegrationMarquageJSON : en sortie structurée, le marquage occupe
// des champs distincts et le contenu reste vierge.
func TestIntegrationMarquageJSON(t *testing.T) {
	env := serveurIntegration(t, instanceIntegration(t, nil), magasinMemoire(t))
	contenu := "contenu pour script\n"
	identifiant := identifiantDe(t, pousser(t, env, contenu, []string{"--marquage", "incident 4712"}))

	lecture := executer(t, []string{"get", "--argument", "--json", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK {
		t.Fatalf("get --json : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}
	var sortie struct {
		Contenu   string `json:"contenu"`
		Empreinte string `json:"empreinte"`
		Marquage  struct {
			Actif      bool   `json:"actif"`
			Libelle    string `json:"libelle"`
			Complement string `json:"complement"`
		} `json:"marquage"`
	}
	if err := json.Unmarshal([]byte(lecture.stdout), &sortie); err != nil {
		t.Fatalf("sortie non JSON : %v (%q)", err, lecture.stdout)
	}
	if sortie.Contenu != contenu {
		t.Fatalf("contenu = %q, attendu %q (vierge de tout marquage)", sortie.Contenu, contenu)
	}
	if !sortie.Marquage.Actif || sortie.Marquage.Libelle != "DIFFUSION RESTREINTE" || sortie.Marquage.Complement != "incident 4712" {
		t.Fatalf("marquage = %+v", sortie.Marquage)
	}
	if sortie.Empreinte == "" {
		t.Error("empreinte absente de la sortie JSON")
	}
}

// TestIntegrationSansMarquage (MARQ-2) : instance sans marquage — la
// restitution est rigoureusement le contenu, même avec un complément.
func TestIntegrationSansMarquage(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["marquage"] = map[string]any{"actif": false}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	contenu := "contenu sans marquage\n"
	identifiant := identifiantDe(t, pousser(t, env, contenu, []string{"--marquage", "complément ignoré"}))

	lecture := executer(t, []string{"get", "--argument", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK || lecture.stdout != contenu {
		t.Fatalf("contenu rendu = %q, attendu %q (MARQ-2 : rien en tête)", lecture.stdout, contenu)
	}
}
