package cli

import (
	"bytes"
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

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
	"ardoise.pm/internal/store"
)

// serveurIntegrationJetons expose le Handler derrière TLS avec une table de
// jetons explicite (plusieurs identités) et retourne l'environnement commun
// (endpoint, AC) — le jeton de chaque identité est ajouté par l'appelant.
func serveurIntegrationJetons(t *testing.T, inst *config.Instance, magasin store.Magasin, jetons *server.Jetons) map[string]string {
	t.Helper()
	ts := httptest.NewTLSServer(server.Handler(inst, magasin, jetons, server.Dependances{}))
	t.Cleanup(ts.Close)
	cheminAC := filepath.Join(t.TempDir(), "ac.pem")
	pemAC := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(cheminAC, pemAC, 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"ARDOISE_ENDPOINT": ts.URL, "ARDOISE_AC": cheminAC}
}

// jetonFactice est un authentifiant factice à préfixe GitHub (36 caractères
// après « ghp_ »), jamais un vrai secret.
const jetonFactice = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// contenuAvecSecret est un contenu de test portant un secret en ligne 2.
const contenuAvecSecret = "extrait de déploiement\ntoken=" + jetonFactice + "\nfin\n"

func avecConfirmation(reponse bool, appels *int) func(*Contexte) {
	return func(ctx *Contexte) {
		ctx.Confirmer = func(string) (bool, error) {
			if appels != nil {
				*appels++
			}
			return reponse, nil
		}
	}
}

func TestModeSecretsEffectif(t *testing.T) {
	cas := []struct {
		instance, drapeau, attendu string
	}{
		{"bloquer", "", "bloquer"},
		{"bloquer", "signaler", "bloquer"},
		{"bloquer", "demander", "bloquer"},
		{"demander", "", "demander"},
		{"demander", "bloquer", "bloquer"},
		{"demander", "signaler", "demander"},
		{"signaler", "", "signaler"},
		{"signaler", "demander", "demander"},
		{"signaler", "bloquer", "bloquer"},
		{"desactive", "", "desactive"},
		{"desactive", "signaler", "signaler"},
		{"desactive", "demander", "demander"},
		{"desactive", "bloquer", "bloquer"},
		{"", "", "demander"},          // instance inconnue : prudence
		{"fantaisie", "", "demander"}, // valeur étrangère : prudence
	}
	for _, c := range cas {
		if obtenu := modeSecretsEffectif(c.instance, c.drapeau); obtenu != c.attendu {
			t.Errorf("modeSecretsEffectif(%q, %q) = %q, attendu %q", c.instance, c.drapeau, obtenu, c.attendu)
		}
	}
}

func TestPushSecretsBloquer(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "bloquer"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))

	r := pousser(t, env, contenuAvecSecret, nil)
	if r.code != CodeSecretDetecte {
		t.Fatalf("code = %d, attendu %d (stderr : %s)", r.code, CodeSecretDetecte, r.stderr)
	}
	if !strings.Contains(r.stderr, "secret détecté") || !strings.Contains(r.stderr, "ligne 2") {
		t.Errorf("détection absente du stderr :\n%s", r.stderr)
	}
	// L'alerte est expurgée : jamais le secret lui-même, seulement « ghp_… ».
	if strings.Contains(r.stderr, jetonFactice) || strings.Contains(r.stdout, jetonFactice) {
		t.Error("le secret détecté fuit dans la sortie")
	}
	if !strings.Contains(r.stderr, "ghp_…") {
		t.Errorf("extrait expurgé absent :\n%s", r.stderr)
	}
	// « --sans-confirmation » ne contourne JAMAIS un blocage.
	r = pousser(t, env, contenuAvecSecret, []string{"-y"})
	if r.code != CodeSecretDetecte {
		t.Fatalf("bloquer + -y : code = %d, attendu %d", r.code, CodeSecretDetecte)
	}
	// « --silencieux » ne cache pas un refus.
	r = pousser(t, env, contenuAvecSecret, []string{"-q"})
	if r.code != CodeSecretDetecte || !strings.Contains(r.stderr, "secret détecté") {
		t.Fatalf("bloquer + -q : code = %d, stderr = %q", r.code, r.stderr)
	}
	// Un contenu sans secret passe.
	if r := pousser(t, env, "rien de sensible ici\n", nil); r.code != CodeOK {
		t.Fatalf("contenu sain : code = %d (stderr : %s)", r.code, r.stderr)
	}
}

func TestPushSecretsDemander(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "demander"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))

	// Confirmation acceptée : le dépôt se poursuit.
	appels := 0
	r := pousser(t, env, contenuAvecSecret, nil, avecConfirmation(true, &appels))
	if r.code != CodeOK || appels != 1 {
		t.Fatalf("confirmation acceptée : code = %d, %d appel(s) (stderr : %s)", r.code, appels, r.stderr)
	}
	// Confirmation refusée (défaut Non) : code 4.
	r = pousser(t, env, contenuAvecSecret, nil, avecConfirmation(false, nil))
	if r.code != CodeSecretDetecte {
		t.Fatalf("confirmation refusée : code = %d", r.code)
	}
	// Aucun terminal (Confirmer nil) et pas de -y : refus code 4.
	r = pousser(t, env, contenuAvecSecret, nil)
	if r.code != CodeSecretDetecte || !strings.Contains(r.stderr, "aucun terminal") {
		t.Fatalf("sans terminal : code = %d, stderr = %q", r.code, r.stderr)
	}
	// -y saute la question sans la poser ; les détections restent affichées.
	appels = 0
	r = pousser(t, env, contenuAvecSecret, []string{"-y"}, avecConfirmation(true, &appels))
	if r.code != CodeOK || appels != 0 {
		t.Fatalf("-y : code = %d, %d appel(s)", r.code, appels)
	}
	if !strings.Contains(r.stderr, "secret détecté") {
		t.Errorf("-y : détections absentes du stderr :\n%s", r.stderr)
	}
}

func TestPushSecretsSignalerEtDesactive(t *testing.T) {
	instSignaler := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "signaler"}
	})
	env := serveurIntegration(t, instSignaler, magasinMemoire(t))
	r := pousser(t, env, contenuAvecSecret, nil)
	if r.code != CodeOK || !strings.Contains(r.stderr, "avertissement") {
		t.Fatalf("signaler : code = %d, stderr = %q", r.code, r.stderr)
	}
	// « --silencieux » supprime l'avertissement informatif de « signaler ».
	r = pousser(t, env, contenuAvecSecret, []string{"-q"})
	if r.code != CodeOK || strings.Contains(r.stderr, "secret détecté") {
		t.Fatalf("signaler + -q : code = %d, stderr = %q", r.code, r.stderr)
	}
	// L'utilisateur peut durcir : --secrets bloquer l'emporte sur signaler.
	if r := pousser(t, env, contenuAvecSecret, []string{"--secrets", "bloquer"}); r.code != CodeSecretDetecte {
		t.Fatalf("signaler durci en bloquer : code = %d", r.code)
	}

	instDesactive := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	envDesactive := serveurIntegration(t, instDesactive, magasinMemoire(t))
	// Instance « desactive » et rien demandé : aucune détection.
	r = pousser(t, envDesactive, contenuAvecSecret, nil)
	if r.code != CodeOK || strings.Contains(r.stderr, "secret détecté") {
		t.Fatalf("desactive : code = %d, stderr = %q", r.code, r.stderr)
	}
	// Mais l'utilisateur peut réactiver localement.
	if r := pousser(t, envDesactive, contenuAvecSecret, []string{"--secrets", "bloquer"}); r.code != CodeSecretDetecte {
		t.Fatalf("desactive + --secrets bloquer : code = %d", r.code)
	}
}

// avecCache branche un répertoire de cache dédié dans l'environnement.
func avecCache(t *testing.T, env map[string]string) string {
	t.Helper()
	repertoire := filepath.Join(t.TempDir(), "cache")
	env["ARDOISE_CACHE"] = repertoire
	return repertoire
}

func TestIntegrationCacheBorne(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["cache"] = map[string]any{"politique": "borne"}
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	repertoire := avecCache(t, env)
	contenu := "contenu mis en cache\n"

	identifiant := identifiantDe(t, pousser(t, env, contenu, []string{"-b"}))

	// Première lecture : consomme l'ardoise (lecture unique) et alimente le
	// cache local.
	lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if lecture.code != CodeOK {
		t.Fatalf("get : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}
	entrees, err := os.ReadDir(repertoire)
	if err != nil || len(entrees) != 2 {
		t.Fatalf("cache après get : %v (%v)", entrees, err)
	}

	// « --cache-seul » : sert sans contacter l'instance (l'ardoise y est
	// d'ailleurs déjà détruite), déchiffrement et marquage identiques.
	seul := executer(t, []string{"get", "--cache-seul", identifiant}, avecEnvironnement(env))
	if seul.code != CodeOK || seul.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("--cache-seul : code = %d, stdout = %q (stderr : %s)", seul.code, seul.stdout, seul.stderr)
	}

	// Lecture par défaut après consommation : l'instance répond code 5, le
	// cache local prend le relais (ADR-013 : la commande se rejoue).
	relecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
	if relecture.code != CodeOK || relecture.stdout != enTeteMarquageIntegration+contenu {
		t.Fatalf("relecture via cache : code = %d, stdout = %q (stderr : %s)", relecture.code, relecture.stdout, relecture.stderr)
	}
	if !strings.Contains(relecture.stderr, "cache local") {
		t.Errorf("le service depuis le cache doit être annoncé :\n%s", relecture.stderr)
	}

	// « --sans-cache » : ni lecture ni repli — l'instance répond code 5.
	sans := executer(t, []string{"get", "--sans-cache", identifiant}, avecEnvironnement(env))
	if sans.code != CodeIntrouvable {
		t.Fatalf("--sans-cache après consommation : code = %d, attendu %d", sans.code, CodeIntrouvable)
	}

	// L'empreinte vérifiée s'applique aussi depuis le cache.
	empreinteFausse := strings.Repeat("0", 64)
	mauvaise := executer(t, []string{"get", "--cache-seul", "--verifier-empreinte", empreinteFausse, identifiant}, avecEnvironnement(env))
	if mauvaise.code != CodeErreur || !strings.Contains(mauvaise.stderr, "empreinte incohérente") {
		t.Fatalf("--verifier-empreinte depuis le cache : code = %d, stderr = %q", mauvaise.code, mauvaise.stderr)
	}
}

func TestIntegrationCacheInterditEtSansCache(t *testing.T) {
	// Politique par défaut (« interdit », CACHE-1) : rien n'est jamais écrit.
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	repertoire := avecCache(t, env)

	identifiant := identifiantDe(t, pousser(t, env, "jamais en cache\n", nil))
	if r := executer(t, []string{"get", identifiant}, avecEnvironnement(env)); r.code != CodeOK {
		t.Fatalf("get : code = %d", r.code)
	}
	if _, err := os.Stat(repertoire); !os.IsNotExist(err) {
		t.Errorf("politique « interdit » : le répertoire de cache ne doit pas exister (%v)", err)
	}

	// Politique « borne » mais « --sans-cache » : rien d'écrit non plus.
	instBorne := instanceIntegration(t, func(m map[string]map[string]any) {
		m["cache"] = map[string]any{"politique": "borne"}
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	envBorne := serveurIntegration(t, instBorne, magasinMemoire(t))
	repertoireBorne := avecCache(t, envBorne)
	identifiant = identifiantDe(t, pousser(t, envBorne, "pas celui-ci\n", nil))
	if r := executer(t, []string{"get", "--sans-cache", identifiant}, avecEnvironnement(envBorne)); r.code != CodeOK {
		t.Fatalf("get --sans-cache : code = %d", r.code)
	}
	if _, err := os.Stat(repertoireBorne); !os.IsNotExist(err) {
		t.Errorf("« --sans-cache » : le répertoire de cache ne doit pas exister (%v)", err)
	}
}

// TestIntegrationCacheSansMatiereSensible vérifie l'invariant ADR-013 de
// bout en bout : les octets du cache ne contiennent ni le clair, ni le
// fragment de clé, ni l'identifiant serveur.
func TestIntegrationCacheSansMatiereSensible(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["cache"] = map[string]any{"politique": "borne"}
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	repertoire := avecCache(t, env)
	contenu := "clair jamais écrit sur le poste"

	identifiant := identifiantDe(t, pousser(t, env, contenu, nil))
	id, fragment, _ := strings.Cut(identifiant, "#")
	if r := executer(t, []string{"get", identifiant}, avecEnvironnement(env)); r.code != CodeOK {
		t.Fatalf("get : code = %d", r.code)
	}
	entrees, err := os.ReadDir(repertoire)
	if err != nil || len(entrees) == 0 {
		t.Fatalf("cache vide : %v (%v)", entrees, err)
	}
	empreinteID := hex.EncodeToString(func() []byte { h := sha256.Sum256([]byte(id)); return h[:] }())
	for _, entree := range entrees {
		if !strings.HasPrefix(entree.Name(), empreinteID) {
			t.Errorf("nom de fichier %s : attendu l'empreinte de l'identifiant serveur", entree.Name())
		}
		donnees, err := os.ReadFile(filepath.Join(repertoire, entree.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for nom, interdit := range map[string]string{"clair": contenu, "fragment de clé": fragment, "identifiant serveur": id} {
			if bytes.Contains(donnees, []byte(interdit)) {
				t.Errorf("%s : contient le %s", entree.Name(), nom)
			}
		}
	}
}

func TestIntegrationPurge(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["cache"] = map[string]any{"politique": "borne"}
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	avecCache(t, env)

	identifiant := identifiantDe(t, pousser(t, env, "à purger plus tard\n", []string{"-t", "2h"}))
	if r := executer(t, []string{"get", identifiant}, avecEnvironnement(env)); r.code != CodeOK {
		t.Fatalf("get : code = %d", r.code)
	}
	// L'entrée n'est pas expirée : la purge par défaut la conserve.
	r := executer(t, []string{"purge", "--json"}, avecEnvironnement(env))
	var decompte struct{ Supprimees, Conservees int }
	if err := json.Unmarshal([]byte(r.stdout), &decompte); err != nil || r.code != CodeOK {
		t.Fatalf("purge --json : %q (%v)", r.stdout, err)
	}
	if decompte.Supprimees != 0 || decompte.Conservees != 1 {
		t.Errorf("purge par défaut : %+v", decompte)
	}
	// « --tout » emporte tout.
	r = executer(t, []string{"purge", "--tout", "--json"}, avecEnvironnement(env))
	if err := json.Unmarshal([]byte(r.stdout), &decompte); err != nil || decompte.Supprimees != 1 {
		t.Errorf("purge --tout : %q (%v)", r.stdout, err)
	}
	// Le cache est vide : « --cache-seul » répond code 5.
	if r := executer(t, []string{"get", "--cache-seul", identifiant}, avecEnvironnement(env)); r.code != CodeIntrouvable {
		t.Errorf("--cache-seul après purge : code = %d", r.code)
	}
}

// jetonsIdentites monte une instance à jetons pour plusieurs identités et
// retourne l'environnement client de chacune.
func serveurMultiIdentites(t *testing.T, inst *config.Instance, magasin store.Magasin, identites []string) map[string]map[string]string {
	t.Helper()
	table := map[string]string{}
	repertoire := t.TempDir()
	chemins := map[string]string{}
	for i, identite := range identites {
		jeton := fmt.Sprintf("jeton-%s", identite)
		empreinte := sha256.Sum256([]byte(jeton))
		table[identite] = hex.EncodeToString(empreinte[:])
		chemin := filepath.Join(repertoire, fmt.Sprintf("jeton-%d", i))
		if err := os.WriteFile(chemin, []byte(jeton+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		chemins[identite] = chemin
	}
	donnees, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	jetons, err := server.AnalyserJetons(donnees)
	if err != nil {
		t.Fatal(err)
	}
	// Réutilise l'infrastructure TLS de serveurIntegrationAvec via un
	// serveur monté à la main.
	envCommun := serveurIntegrationJetons(t, inst, magasin, jetons)
	environnements := map[string]map[string]string{}
	for identite, chemin := range chemins {
		env := map[string]string{}
		for cle, valeur := range envCommun {
			env[cle] = valeur
		}
		env["ARDOISE_JETON"] = chemin
		environnements[identite] = env
	}
	return environnements
}

func TestIntegrationPourEtMultiDestinataires(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	envs := serveurMultiIdentites(t, inst, magasinMemoire(t), []string{"alice.durand", "bob.petit", "mallory.evein"})
	contenu := "note pour alice et bob\n"

	// Matériel de destinataire généré par « ardoise cle --generer ».
	repertoireCles := t.TempDir()
	annuaire := map[string]string{}
	for _, identite := range []string{"alice.durand", "bob.petit"} {
		chemin := filepath.Join(repertoireCles, identite+".cle")
		r := executer(t, []string{"cle", "--generer", "--fichier", chemin})
		if r.code != CodeOK {
			t.Fatalf("cle --generer : code = %d (stderr : %s)", r.code, r.stderr)
		}
		annuaire[identite] = strings.TrimSpace(r.stdout)
		infos, err := os.Stat(chemin)
		if err != nil {
			t.Fatal(err)
		}
		if mode := infos.Mode().Perm(); mode != 0o600 {
			t.Errorf("clé privée %s : droits %04o, attendu 0600", chemin, mode)
		}
		// Une clé existante n'est jamais écrasée.
		if r := executer(t, []string{"cle", "--generer", "--fichier", chemin}); r.code != CodeErreur {
			t.Errorf("réécriture de clé : code = %d, attendu %d", r.code, CodeErreur)
		}
	}
	donneesAnnuaire, err := json.Marshal(annuaire)
	if err != nil {
		t.Fatal(err)
	}
	cheminAnnuaire := filepath.Join(repertoireCles, "annuaire.json")
	if err := os.WriteFile(cheminAnnuaire, donneesAnnuaire, 0o600); err != nil {
		t.Fatal(err)
	}

	// Dépôt par alice : --pour alice,bob avec annuaire → CHIF-MD, sentinelle
	// « #md » (aucune clé dans l'identifiant).
	envAlice := envs["alice.durand"]
	envAlice["ARDOISE_ANNUAIRE"] = cheminAnnuaire
	r := pousser(t, envAlice, contenu, []string{"--pour", "alice.durand,bob.petit"})
	identifiant := identifiantDe(t, r)
	if !strings.HasSuffix(identifiant, "#md") {
		t.Fatalf("identifiant = %q, attendu la sentinelle « #md »", identifiant)
	}

	// Chaque destinataire ouvre avec sa propre clé privée.
	for _, identite := range []string{"alice.durand", "bob.petit"} {
		env := envs[identite]
		env["ARDOISE_CLE_PRIVEE"] = filepath.Join(repertoireCles, identite+".cle")
		lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(env))
		if lecture.code != CodeOK || lecture.stdout != enTeteMarquageIntegration+contenu {
			t.Fatalf("%s : code = %d, stdout = %q (stderr : %s)", identite, lecture.code, lecture.stdout, lecture.stderr)
		}
	}

	// Mallory, authentifiée mais non désignée : l'instance répond comme pour
	// une ardoise inexistante — code 5, avant même toute cryptographie.
	envMallory := envs["mallory.evein"]
	refus := executer(t, []string{"get", identifiant}, avecEnvironnement(envMallory))
	if refus.code != CodeIntrouvable {
		t.Fatalf("mallory : code = %d, attendu %d (stderr : %s)", refus.code, CodeIntrouvable, refus.stderr)
	}
}

func TestIntegrationPourRepliSansCle(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	envs := serveurMultiIdentites(t, inst, magasinMemoire(t), []string{"alice.durand", "bob.petit"})
	envAlice := envs["alice.durand"]

	// Annuaire sans la clé de bob : repli signalé, désignation serveur seule
	// — le chiffrement retombe sur le schéma de l'instance (fragment de clé).
	repertoire := t.TempDir()
	r := executer(t, []string{"cle", "--generer", "--fichier", filepath.Join(repertoire, "alice.cle")})
	if r.code != CodeOK {
		t.Fatal(r.stderr)
	}
	annuaire := fmt.Sprintf(`{"alice.durand": %q}`, strings.TrimSpace(r.stdout))
	cheminAnnuaire := filepath.Join(repertoire, "annuaire.json")
	if err := os.WriteFile(cheminAnnuaire, []byte(annuaire), 0o600); err != nil {
		t.Fatal(err)
	}
	envAlice["ARDOISE_ANNUAIRE"] = cheminAnnuaire

	depot := pousser(t, envAlice, "contenu\n", []string{"--pour", "alice.durand,bob.petit"})
	identifiant := identifiantDe(t, depot)
	if strings.HasSuffix(identifiant, "#md") {
		t.Fatal("repli attendu : pas de sentinelle « #md »")
	}
	if !strings.Contains(depot.stderr, "Aucune clé publique pour « bob.petit »") {
		t.Errorf("le repli doit être signalé :\n%s", depot.stderr)
	}
	// La désignation serveur demeure : bob (désigné) lit, avec le fragment.
	if lecture := executer(t, []string{"get", identifiant}, avecEnvironnement(envs["bob.petit"])); lecture.code != CodeOK {
		t.Fatalf("bob : code = %d (stderr : %s)", lecture.code, lecture.stderr)
	}

	// Un groupe désigné fait toujours retomber sur la vérification serveur.
	groupe := pousser(t, envAlice, "contenu\n", []string{"--pour", "alice.durand,@equipe"})
	identifiantGroupe := identifiantDe(t, groupe)
	if strings.HasSuffix(identifiantGroupe, "#md") {
		t.Fatal("groupe désigné : pas de chiffrement multi-destinataires")
	}
	if !strings.Contains(groupe.stderr, "Groupe @equipe désigné") {
		t.Errorf("le repli de groupe doit être signalé :\n%s", groupe.stderr)
	}
}

func TestIntegrationPourRefuseSousDeclaratif(t *testing.T) {
	inst := instanceIntegration(t, func(m map[string]map[string]any) {
		m["auth"] = map[string]any{"mecanisme": "declaratif"}
		m["analyse"] = map[string]any{"secrets_client": "desactive"}
	})
	env := serveurIntegration(t, inst, magasinMemoire(t))
	r := pousser(t, env, "contenu\n", []string{"--pour", "alice.durand"})
	if r.code != CodeRefusPolitique {
		t.Fatalf("--pour sous declaratif : code = %d, attendu %d (stderr : %s)", r.code, CodeRefusPolitique, r.stderr)
	}
	if !strings.Contains(r.stderr, "falsifiable") {
		t.Errorf("le refus doit être motivé :\n%s", r.stderr)
	}
}

func TestCleGenererValidation(t *testing.T) {
	if r := executer(t, []string{"cle"}); r.code != CodeUsage {
		t.Errorf("cle sans --generer : code = %d", r.code)
	}
	if r := executer(t, []string{"cle", "--generer"}); r.code != CodeUsage {
		t.Errorf("cle --generer sans fichier : code = %d (stderr : %s)", r.code, r.stderr)
	}
	// --json restitue la clé publique et le fichier.
	chemin := filepath.Join(t.TempDir(), "poste.cle")
	r := executer(t, []string{"cle", "--generer", "--fichier", chemin, "--json"})
	if r.code != CodeOK {
		t.Fatalf("cle --generer --json : code = %d (stderr : %s)", r.code, r.stderr)
	}
	var sortie struct {
		ClePublique string `json:"cle_publique"`
		Fichier     string `json:"fichier"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &sortie); err != nil || sortie.ClePublique == "" || sortie.Fichier != chemin {
		t.Errorf("sortie JSON : %q (%v)", r.stdout, err)
	}
}
