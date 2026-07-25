package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

type resultat struct {
	code   int
	stdout string
	stderr string
}

// executer lance la CLI dans un contexte entièrement substitué : terminal
// simulé, environnement vide, aucune configuration client.
func executer(t *testing.T, args []string, options ...func(*Contexte)) resultat {
	t.Helper()
	var stdout, stderr bytes.Buffer
	ctx := &Contexte{
		Args:      args,
		Stdin:     strings.NewReader(""),
		Stdout:    &stdout,
		Stderr:    &stderr,
		Getenv:    func(string) string { return "" },
		StdinTTY:  true,
		StdoutTTY: false,
	}
	for _, option := range options {
		option(ctx)
	}
	code := Executer(ctx)
	return resultat{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func avecEnvironnement(env map[string]string) func(*Contexte) {
	return func(ctx *Contexte) {
		ctx.Getenv = func(nom string) string { return env[nom] }
	}
}

func TestSansArgumentsSurTerminal(t *testing.T) {
	r := executer(t, nil)
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d", r.code, CodeUsage)
	}
	if !strings.Contains(r.stderr, "usage") {
		t.Errorf("l'usage doit être rappelé :\n%s", r.stderr)
	}
}

func TestPushImpliciteEntreeRedirigee(t *testing.T) {
	// Sans sous-commande et avec l'entrée redirigée, « push » est implicite :
	// sans instance configurée, c'est bien le dépôt qui échoue (code 2).
	r := executer(t, nil, func(ctx *Contexte) { ctx.StdinTTY = false })
	if r.code != CodeUsage {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeUsage, r.stderr)
	}
	if !strings.Contains(r.stderr, "aucune instance indiquée") {
		t.Errorf("message attendu :\n%s", r.stderr)
	}
}

func TestArgumentInconnuBasculeVersPush(t *testing.T) {
	// « ardoise -t 30m -p -f fichier » : push implicite avec options ; les
	// options passent l'analyse et le dépôt bute sur l'absence d'instance.
	r := executer(t, []string{"-t", "30m", "-p", "-f", "extrait.log"})
	if r.code != CodeUsage || !strings.Contains(r.stderr, "aucune instance indiquée") {
		t.Fatalf("code = %d, stderr = %q", r.code, r.stderr)
	}
}

func TestAideGenerale(t *testing.T) {
	for _, args := range [][]string{{"--aide"}, {"-h"}, {"aide"}} {
		r := executer(t, args)
		if r.code != CodeOK {
			t.Errorf("%v : code = %d, attendu 0", args, r.code)
		}
		if !strings.Contains(r.stdout, "Sous-commandes") {
			t.Errorf("%v : aide attendue sur stdout", args)
		}
	}
}

func TestAideParCommande(t *testing.T) {
	commandes := map[string]string{
		"push":    "--lecture-unique",
		"get":     "--verifier-empreinte",
		"info":    "configuration effective",
		"purge":   "--tout",
		"serve":   "--verifier",
		"version": "empreinte",
	}
	for nom, motif := range commandes {
		r := executer(t, []string{nom, "--aide"})
		if r.code != CodeOK {
			t.Errorf("%s --aide : code = %d, attendu 0 (stderr : %s)", nom, r.code, r.stderr)
		}
		if !strings.Contains(strings.ToLower(r.stdout), strings.ToLower(motif)) {
			t.Errorf("%s --aide : motif %q absent :\n%s", nom, motif, r.stdout)
		}
	}
}

func TestPushValidationOptions(t *testing.T) {
	cas := []struct {
		nom  string
		args []string
		code int
	}{
		// Les options valides passent l'analyse ; sans instance configurée,
		// le dépôt s'arrête sur « aucune instance indiquée » (code 2).
		{"options valides", []string{"push", "-t", "30m", "-b", "--secrets", "bloquer", "--pour", "alice.durand,@equipe-reseau", "--marquage", "URGENT"}, CodeUsage},
		{"fichier positionnel", []string{"push", "extrait.log"}, CodeUsage},
		{"duree invalide", []string{"push", "-t", "toujours"}, CodeUsage},
		{"secrets invalide", []string{"push", "--secrets", "ignorer"}, CodeUsage},
		{"pour invalide", []string{"push", "--pour", "alice durand"}, CodeUsage},
		{"pour vide", []string{"push", "--pour", "alice,,bob"}, CodeUsage},
		{"fichier en double", []string{"push", "-f", "a.log", "b.log"}, CodeUsage},
		{"deux positionnels", []string{"push", "a.log", "b.log"}, CodeUsage},
		{"option inconnue", []string{"push", "--televerser"}, CodeUsage},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r := executer(t, c.args)
			if r.code != c.code {
				t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, c.code, r.stderr)
			}
		})
	}
}

func TestGetValidationOptions(t *testing.T) {
	empreinte := strings.Repeat("ab", 32)
	// Identifiant bien formé : 12 caractères [a-z2-9] et un fragment de
	// 32 octets en base64url brut.
	identifiant := "abcdefghij29#" + strings.Repeat("A", 43)
	cas := []struct {
		nom   string
		args  []string
		code  int
		motif string
	}{
		// Un identifiant valide passe l'analyse ; sans instance configurée,
		// la récupération s'arrête sur « aucune instance indiquée ».
		{"identifiant valide", []string{"get", identifiant}, CodeUsage, "aucune instance indiquée"},
		{"empreinte valide", []string{"get", "--verifier-empreinte", empreinte, identifiant}, CodeUsage, "aucune instance indiquée"},
		{"empreinte prefixee", []string{"get", "--verifier-empreinte", "sha256:" + empreinte, identifiant}, CodeUsage, "aucune instance indiquée"},
		{"identifiant malformé", []string{"get", "a7f3k9x2m4n6#Zt8mQ4vP1nK"}, CodeUsage, "identifiant invalide"},
		{"tiret sans entrée", []string{"get", "-"}, CodeUsage, "aucun identifiant"},
		{"identifiant manquant", []string{"get"}, CodeUsage, "IDENTIFIANT requis"},
		{"cache contradictoire", []string{"get", "-n", "--cache-seul", identifiant}, CodeUsage, "exclusifs"},
		// « --cache-seul » sur un cache vide : même sémantique que le code 5
		// du serveur (absente, expirée ou jamais mise en cache).
		{"cache seul sans entrée", []string{"get", "--cache-seul", identifiant}, CodeIntrouvable, "cache local"},
		{"empreinte invalide", []string{"get", "--verifier-empreinte", "zz12", identifiant}, CodeUsage, "empreinte invalide"},
		{"deux identifiants", []string{"get", identifiant, identifiant}, CodeUsage, "argument inattendu"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r := executer(t, c.args)
			if r.code != c.code {
				t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, c.code, r.stderr)
			}
			if !strings.Contains(r.stderr, c.motif) {
				t.Errorf("motif %q absent de :\n%s", c.motif, r.stderr)
			}
		})
	}
}

func TestPurge(t *testing.T) {
	// Un cache absent n'est jamais une erreur : rien à purger (0 partout).
	env := map[string]string{"ARDOISE_CACHE": filepath.Join(t.TempDir(), "inexistant")}
	if r := executer(t, []string{"purge"}, avecEnvironnement(env)); r.code != CodeOK {
		t.Errorf("purge : code = %d, attendu %d (stderr : %s)", r.code, CodeOK, r.stderr)
	}
	if r := executer(t, []string{"purge", "--tout"}, avecEnvironnement(env)); r.code != CodeOK {
		t.Errorf("purge --tout : code = %d, attendu %d", r.code, CodeOK)
	}
	r := executer(t, []string{"purge", "--json"}, avecEnvironnement(env))
	var decompte struct {
		Supprimees *int `json:"supprimees"`
		Conservees *int `json:"conservees"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &decompte); err != nil || r.code != CodeOK {
		t.Fatalf("purge --json : code = %d, stdout = %q (%v)", r.code, r.stdout, err)
	}
	if decompte.Supprimees == nil || *decompte.Supprimees != 0 || decompte.Conservees == nil || *decompte.Conservees != 0 {
		t.Errorf("purge --json : décomptes inattendus : %s", r.stdout)
	}
	if r := executer(t, []string{"purge", "reste"}); r.code != CodeUsage {
		t.Errorf("purge avec positionnel : code = %d, attendu %d", r.code, CodeUsage)
	}
}

func TestVersion(t *testing.T) {
	r := executer(t, []string{"version"})
	if r.code != CodeOK {
		t.Fatalf("code = %d (stderr : %s)", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "ardoise "+Version) {
		t.Errorf("version absente :\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "sha256:") {
		t.Errorf("empreinte du binaire absente :\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, IDCompilation) {
		t.Errorf("identifiant de compilation absent :\n%s", r.stdout)
	}
}

func TestVersionJSON(t *testing.T) {
	r := executer(t, []string{"version", "--json"})
	if r.code != CodeOK {
		t.Fatalf("code = %d", r.code)
	}
	var corps struct {
		Version     string `json:"version"`
		Empreinte   string `json:"empreinte"`
		Compilation string `json:"compilation"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &corps); err != nil {
		t.Fatalf("JSON illisible : %v\n%s", err, r.stdout)
	}
	if corps.Version != Version || !strings.HasPrefix(corps.Empreinte, "sha256:") || corps.Compilation != IDCompilation {
		t.Errorf("corps inattendu : %+v", corps)
	}
}

func TestCodePourStatutHTTP(t *testing.T) {
	cas := map[int]int{
		401: CodeAuthRefusee,
		403: CodeAuthRefusee,
		404: CodeIntrouvable,
		410: CodeIntrouvable,
		413: CodeTailleDepassee,
		422: CodeRefusPolitique,
		451: CodeAnalyseDefavorable,
		500: CodeErreur,
		418: CodeErreur,
	}
	for statut, attendu := range cas {
		if obtenu := CodePourStatutHTTP(statut); obtenu != attendu {
			t.Errorf("CodePourStatutHTTP(%d) = %d, attendu %d", statut, obtenu, attendu)
		}
	}
}

func TestTableCodesRetour(t *testing.T) {
	// La table du manuel, exactement (0..9).
	valeurs := []int{CodeOK, CodeErreur, CodeUsage, CodeRefusPolitique, CodeSecretDetecte,
		CodeIntrouvable, CodeAuthRefusee, CodeAnalyseDefavorable, CodeTailleDepassee, CodeInjoignable}
	for i, v := range valeurs {
		if v != i {
			t.Errorf("code n°%d = %d", i, v)
		}
	}
}

func TestDetectionCouleur(t *testing.T) {
	cas := []struct {
		nom         string
		sansCouleur bool
		tty         bool
		env         string
		attendu     bool
	}{
		{"terminal", false, true, "", true},
		{"option sans-couleur", true, true, "", false},
		{"variable ARDOISE_NO_COLOR", false, true, "1", false},
		{"sortie redirigée", false, false, "", false},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			ctx := &Contexte{
				StdoutTTY: c.tty,
				Getenv:    func(nom string) string { return map[string]string{"ARDOISE_NO_COLOR": c.env}[nom] },
			}
			s := nouvelleSortie(ctx, &optionsCommunes{sansCouleur: c.sansCouleur})
			if s.couleur != c.attendu {
				t.Errorf("couleur = %v, attendu %v", s.couleur, c.attendu)
			}
			if c.attendu && !strings.Contains(s.gras("x"), "\x1b[1m") {
				t.Error("gras attendu avec couleur active")
			}
			if !c.attendu && s.gras("x") != "x" {
				t.Error("aucune séquence attendue sans couleur")
			}
		})
	}
}

func TestSortieSilencieuse(t *testing.T) {
	var stderr bytes.Buffer
	s := &sortie{stderr: &stderr, silencieux: true}
	s.infof("message informatif")
	if stderr.Len() != 0 {
		t.Errorf("aucun message attendu en mode silencieux, obtenu %q", stderr.String())
	}
	s.silencieux = false
	s.infof("message informatif")
	if !strings.Contains(stderr.String(), "message informatif") {
		t.Errorf("message attendu, obtenu %q", stderr.String())
	}
}
