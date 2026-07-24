package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// configComplete reproduit l'exemple du manuel (docs/man.md), en JSON.
func configComplete() map[string]map[string]any {
	return map[string]map[string]any{
		"instance": {
			"nom":    "ardoise-adm-zone-reseau",
			"mode":   "aveugle",
			"ecoute": "127.0.0.1:8443",
		},
		"auth": {
			"mecanisme":      "mtls",
			"ac_clients":     "/etc/ardoise/ac-clients.pem",
			"champ_identite": "CN",
		},
		"contenu": {
			"chiffrement": "cle",
			"taille_max":  "256Kio",
		},
		"retention": {
			"support":        "memoire",
			"lecture_unique": "au-choix",
			"duree_max":      "24h",
			"duree_defaut":   "1h",
		},
		"cache": {
			"politique": "interdit",
		},
		"analyse": {
			"secrets_client": "bloquer",
			"icap_url":       "",
			"icap_delai":     "10s",
			"icap_regles":    "",
		},
		"journal": {
			"destination": "syslog+tls://journal.adm.interne:6514",
			"chainage":    true,
		},
		"transport": {
			"certificat":  "/etc/ardoise/instance.pem",
			"cle":         "/etc/ardoise/instance.key",
			"version_min": "1.3",
			"epinglage":   true,
		},
		"marquage": {
			"actif":   true,
			"libelle": "DIFFUSION RESTREINTE",
		},
	}
}

func enJSON(t *testing.T, m map[string]map[string]any) []byte {
	t.Helper()
	donnees, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("sérialisation du cas de test : %v", err)
	}
	return donnees
}

func analyserSansProbleme(t *testing.T, donnees []byte) *Instance {
	t.Helper()
	inst, problemes, err := Analyser(donnees)
	if err != nil {
		t.Fatalf("Analyser : erreur fatale inattendue %v", err)
	}
	if len(problemes) != 0 {
		t.Fatalf("Analyser : problèmes inattendus %v", problemes)
	}
	return inst
}

func TestChargerFichier(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "ardoise.json")
	if err := os.WriteFile(chemin, enJSON(t, configComplete()), 0o600); err != nil {
		t.Fatal(err)
	}
	inst, problemes, err := Charger(chemin)
	if err != nil {
		t.Fatalf("Charger : %v", err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}
	if inst.Nom != "ardoise-adm-zone-reseau" {
		t.Errorf("nom = %q", inst.Nom)
	}
	if inst.Retention.DureeMax != 24*time.Hour || inst.Retention.DureeDefaut != time.Hour {
		t.Errorf("durées = %v / %v", inst.Retention.DureeMax, inst.Retention.DureeDefaut)
	}
	if inst.Contenu.TailleMax != 256*1024 {
		t.Errorf("taille_max = %d", inst.Contenu.TailleMax)
	}
}

func TestChargerFichierAbsent(t *testing.T) {
	if _, _, err := Charger(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("erreur attendue pour un fichier absent")
	}
}

func TestChampInconnuRefuse(t *testing.T) {
	m := configComplete()
	m["instance"]["telemetrie"] = true
	if _, _, err := Analyser(enJSON(t, m)); err == nil {
		t.Fatal("un champ inconnu doit être une erreur (décodage strict)")
	}
}

func TestSectionInconnueRefusee(t *testing.T) {
	donnees := []byte(`{"instance":{"nom":"x"},"federation":{}}`)
	if _, _, err := Analyser(donnees); err == nil {
		t.Fatal("une section inconnue doit être une erreur (décodage strict)")
	}
}

func TestJSONIllisible(t *testing.T) {
	for _, donnees := range []string{"", "{", `{"instance":{}} {"reste":1}`} {
		if _, _, err := Analyser([]byte(donnees)); err == nil {
			t.Errorf("Analyser(%q) : erreur attendue", donnees)
		}
	}
}

// TestDefautsPrudents vérifie la règle « toute option omise prend sa valeur
// la plus prudente » sur une configuration minimale.
func TestDefautsPrudents(t *testing.T) {
	minimale := map[string]map[string]any{
		"instance":  {"nom": "ardoise-min", "ecoute": "127.0.0.1:8443"},
		"auth":      {"ac_clients": "/etc/ardoise/ac.pem"},
		"transport": {"certificat": "/etc/ardoise/i.pem", "cle": "/etc/ardoise/i.key"},
		"marquage":  {"libelle": "DIFFUSION RESTREINTE"},
	}
	inst := analyserSansProbleme(t, enJSON(t, minimale))

	verifications := []struct {
		nom     string
		obtenu  any
		attendu any
	}{
		{"mode", inst.Mode, ModeAveugle},
		{"auth.mecanisme", inst.Auth.Mecanisme, "mtls-materiel"},
		{"auth.champ_identite", inst.Auth.ChampIdentite, "CN"},
		{"contenu.chiffrement", inst.Contenu.Chiffrement, "cle+motdepasse"},
		{"contenu.taille_max", inst.Contenu.TailleMax, int64(256 * 1024)},
		{"retention.support", inst.Retention.Support, "memoire"},
		{"retention.lecture_unique", inst.Retention.LectureUnique, LectureUniqueImposee},
		{"retention.duree_max", inst.Retention.DureeMax, time.Hour},
		{"retention.duree_defaut", inst.Retention.DureeDefaut, time.Hour},
		{"cache.politique", inst.Cache.Politique, "interdit"},
		{"analyse.secrets_client", inst.Analyse.SecretsClient, "bloquer"},
		{"analyse.icap_delai", inst.Analyse.ICAPDelai, 10 * time.Second},
		{"journal.destination", inst.Journal.Destination, "aucun"},
		{"journal.chainage", inst.Journal.Chainage, false},
		{"transport.version_min", inst.Transport.VersionMin, "1.3"},
		{"transport.epinglage", inst.Transport.Epinglage, true},
		{"marquage.actif", inst.Marquage.Actif, true},
	}
	for _, v := range verifications {
		if v.obtenu != v.attendu {
			t.Errorf("défaut %s = %v, attendu %v", v.nom, v.obtenu, v.attendu)
		}
	}

	// Les options par défaut sont les plus protectrices de chaque dimension.
	p := inst.Politique()
	attendus := map[string]string{
		DimIdentification: "AUTH-1",
		DimContenu:        "CHIF-1",
		DimConservation:   "RET-1",
		DimDureeDeVie:     "TTL-1",
		DimRemanence:      "CACHE-1",
		DimAnalyse:        "ANA-3",
		DimJournalisation: "JOURN-4", // aucune destination ne peut être inventée
		DimTransport:      "TLS-2",
		DimMarquage:       "MARQ-1",
	}
	for dimension, id := range attendus {
		o, ok := p.Option(dimension)
		if !ok || o.ID != id {
			t.Errorf("option %s = %+v, attendu %s", dimension, o, id)
		}
	}
}

func TestDefautChiffrementModeAnalyse(t *testing.T) {
	m := configComplete()
	m["instance"]["mode"] = "analyse"
	delete(m["contenu"], "chiffrement")
	m["analyse"]["icap_url"] = "icap://analyse.interne:1344/reqmod"
	inst := analyserSansProbleme(t, enJSON(t, m))
	if inst.Contenu.Chiffrement != "serveur" {
		t.Errorf("chiffrement = %q, attendu « serveur » (CHIF-4, seule valeur du mode analyse)", inst.Contenu.Chiffrement)
	}
}

func TestDefautDureeDefautBornee(t *testing.T) {
	m := configComplete()
	m["retention"]["duree_max"] = "30m"
	delete(m["retention"], "duree_defaut")
	inst := analyserSansProbleme(t, enJSON(t, m))
	if inst.Retention.DureeDefaut != 30*time.Minute {
		t.Errorf("duree_defaut = %v, attendu 30m (min(1h, duree_max))", inst.Retention.DureeDefaut)
	}
}

func TestDefautChainageAvecCollecteur(t *testing.T) {
	m := configComplete()
	delete(m["journal"], "chainage")
	inst := analyserSansProbleme(t, enJSON(t, m))
	if !inst.Journal.Chainage {
		t.Error("chainage devrait être actif par défaut avec une destination de collecte (JOURN-1)")
	}
}

// TestValidation couvre les énumérations et les contrôles de cohérence
// entre champs. Chaque cas part de la configuration complète valide et la
// mute ; le problème attendu est identifié par son champ.
func TestValidation(t *testing.T) {
	cas := []struct {
		nom   string
		muter func(m map[string]map[string]any)
		champ string // champ du problème attendu ; "" = aucun problème
	}{
		{"valide", func(m map[string]map[string]any) {}, ""},
		{"nom manquant", func(m map[string]map[string]any) { delete(m["instance"], "nom") }, "instance.nom"},
		{"mode inconnu", func(m map[string]map[string]any) { m["instance"]["mode"] = "hybride" }, "instance.mode"},
		{"ecoute invalide", func(m map[string]map[string]any) { m["instance"]["ecoute"] = "pas-une-adresse" }, "instance.ecoute"},
		{"mecanisme inconnu", func(m map[string]map[string]any) { m["auth"]["mecanisme"] = "ntlm" }, "auth.mecanisme"},
		{"ac_clients manquant pour mtls", func(m map[string]map[string]any) { m["auth"]["ac_clients"] = "" }, "auth.ac_clients"},
		{"ac_clients sans objet pour jeton", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "jeton"
			m["auth"]["jetons"] = "/etc/ardoise/jetons.json"
		}, "auth.ac_clients"},
		{"champ_identite inconnu", func(m map[string]map[string]any) { m["auth"]["champ_identite"] = "OU" }, "auth.champ_identite"},
		{"champ_identite SAN nu refusé", func(m map[string]map[string]any) { m["auth"]["champ_identite"] = "SAN" }, "auth.champ_identite"},
		{"champ_identite SAN:email admis", func(m map[string]map[string]any) { m["auth"]["champ_identite"] = "SAN:email" }, ""},
		{"champ_identite SAN:dns admis", func(m map[string]map[string]any) { m["auth"]["champ_identite"] = "SAN:dns" }, ""},
		{"champ_identite SAN:uri admis", func(m map[string]map[string]any) { m["auth"]["champ_identite"] = "SAN:uri" }, ""},
		{"jetons manquant pour jeton", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "jeton"
			m["auth"]["ac_clients"] = ""
		}, "auth.jetons"},
		{"jetons admis pour jeton", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "jeton"
			m["auth"]["ac_clients"] = ""
			m["auth"]["jetons"] = "/etc/ardoise/jetons.json"
		}, ""},
		{"jetons sans objet pour mtls", func(m map[string]map[string]any) {
			m["auth"]["jetons"] = "/etc/ardoise/jetons.json"
		}, "auth.jetons"},
		{"declaratif en mode analyse", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["auth"]["mecanisme"] = "declaratif"
			m["contenu"]["chiffrement"] = "serveur"
			m["analyse"]["icap_url"] = "icap://a.interne:1344/reqmod"
		}, "auth.mecanisme"},
		{"declaratif en mode aveugle admis", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "declaratif"
			m["auth"]["ac_clients"] = ""
		}, ""},
		{"chiffrement inconnu", func(m map[string]map[string]any) { m["contenu"]["chiffrement"] = "rot13" }, "contenu.chiffrement"},
		{"chiffrement serveur en mode aveugle", func(m map[string]map[string]any) { m["contenu"]["chiffrement"] = "serveur" }, "contenu.chiffrement"},
		{"chiffrement cle en mode analyse", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["analyse"]["icap_url"] = "icap://a.interne:1344/reqmod"
		}, "contenu.chiffrement"},
		{"taille invalide", func(m map[string]map[string]any) { m["contenu"]["taille_max"] = "beaucoup" }, "contenu.taille_max"},
		{"support inconnu", func(m map[string]map[string]any) { m["retention"]["support"] = "disque" }, "retention.support"},
		{"lecture_unique inconnue", func(m map[string]map[string]any) { m["retention"]["lecture_unique"] = "parfois" }, "retention.lecture_unique"},
		{"duree_max invalide", func(m map[string]map[string]any) { m["retention"]["duree_max"] = "toujours" }, "retention.duree_max"},
		{"duree_max au-delà de TTL-3", func(m map[string]map[string]any) { m["retention"]["duree_max"] = "169h" }, "retention.duree_max"},
		{"duree_defaut invalide", func(m map[string]map[string]any) { m["retention"]["duree_defaut"] = "-1h" }, "retention.duree_defaut"},
		{"duree_defaut au-delà de duree_max", func(m map[string]map[string]any) { m["retention"]["duree_defaut"] = "48h" }, "retention.duree_defaut"},
		{"cle_magasin manquante avec disque-chiffre", func(m map[string]map[string]any) {
			m["retention"]["support"] = "disque-chiffre"
		}, "retention.cle_magasin"},
		{"disque-chiffre avec cle_magasin admis", func(m map[string]map[string]any) {
			m["retention"]["support"] = "disque-chiffre"
			m["retention"]["cle_magasin"] = "/etc/ardoise/magasin.cle"
			m["retention"]["repertoire"] = "/var/lib/ardoise"
		}, ""},
		{"cle_magasin sans objet avec memoire", func(m map[string]map[string]any) {
			m["retention"]["cle_magasin"] = "/etc/ardoise/magasin.cle"
		}, "retention.cle_magasin"},
		{"repertoire sans objet avec memoire", func(m map[string]map[string]any) {
			m["retention"]["repertoire"] = "/var/lib/ardoise"
		}, "retention.repertoire"},
		{"repertoire vide avec disque-chiffre", func(m map[string]map[string]any) {
			m["retention"]["support"] = "disque-chiffre"
			m["retention"]["cle_magasin"] = "/etc/ardoise/magasin.cle"
			m["retention"]["repertoire"] = ""
		}, "retention.repertoire"},
		{"cache inconnu", func(m map[string]map[string]any) { m["cache"]["politique"] = "toujours" }, "cache.politique"},
		{"secrets_client inconnu", func(m map[string]map[string]any) { m["analyse"]["secrets_client"] = "ignorer" }, "analyse.secrets_client"},
		{"icap_delai invalide", func(m map[string]map[string]any) { m["analyse"]["icap_delai"] = "0s" }, "analyse.icap_delai"},
		{"icap_url manquant en mode analyse", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["contenu"]["chiffrement"] = "serveur"
		}, "analyse.icap_url"},
		{"icap_url en mode aveugle", func(m map[string]map[string]any) { m["analyse"]["icap_url"] = "icap://a.interne:1344/reqmod" }, "analyse.icap_url"},
		{"icap_url invalide", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["contenu"]["chiffrement"] = "serveur"
			m["analyse"]["icap_url"] = "https://pas-icap.interne/"
		}, "analyse.icap_url"},
		{"journal destination inconnue", func(m map[string]map[string]any) { m["journal"]["destination"] = "carnet" }, "journal.destination"},
		{"journal destination syslog en clair refusée", func(m map[string]map[string]any) { m["journal"]["destination"] = "syslog://j.interne:514" }, "journal.destination"},
		{"chainage sans collecteur", func(m map[string]map[string]any) { m["journal"]["destination"] = "fichier" }, "journal.chainage"},
		{"version_min inconnue", func(m map[string]map[string]any) { m["transport"]["version_min"] = "1.0" }, "transport.version_min"},
		{"certificat manquant", func(m map[string]map[string]any) { m["transport"]["certificat"] = "" }, "transport.certificat"},
		{"cle manquante", func(m map[string]map[string]any) { delete(m["transport"], "cle") }, "transport.cle"},
		{"marquage actif sans libelle", func(m map[string]map[string]any) { m["marquage"]["libelle"] = "" }, "marquage.libelle"},
		{"marquage inactif sans libelle admis", func(m map[string]map[string]any) {
			m["marquage"]["actif"] = false
			m["marquage"]["libelle"] = ""
		}, ""},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m := configComplete()
			c.muter(m)
			_, problemes, err := Analyser(enJSON(t, m))
			if err != nil {
				t.Fatalf("erreur fatale inattendue : %v", err)
			}
			if c.champ == "" {
				if len(problemes) != 0 {
					t.Fatalf("problèmes inattendus : %v", problemes)
				}
				return
			}
			for _, p := range problemes {
				if p.Champ == c.champ {
					return
				}
			}
			t.Fatalf("problème attendu sur %q, obtenu : %v", c.champ, problemes)
		})
	}
}

// TestProblemesTousSignales vérifie que la validation ne s'arrête pas au
// premier problème (« --verifier » doit tous les signaler).
func TestProblemesTousSignales(t *testing.T) {
	m := configComplete()
	m["instance"]["mode"] = "hybride"
	m["contenu"]["taille_max"] = "beaucoup"
	m["transport"]["certificat"] = ""
	_, problemes, err := Analyser(enJSON(t, m))
	if err != nil {
		t.Fatalf("erreur fatale inattendue : %v", err)
	}
	if len(problemes) < 3 {
		t.Fatalf("au moins 3 problèmes attendus, obtenu %d : %v", len(problemes), problemes)
	}
}

func TestOptionsExempleManuel(t *testing.T) {
	inst := analyserSansProbleme(t, enJSON(t, configComplete()))
	p := inst.Politique()
	attendus := map[string][2]string{
		DimIdentification: {"AUTH-2", "R"},
		DimContenu:        {"CHIF-2", "R"},
		DimConservation:   {"RET-2", "R"},
		DimDureeDeVie:     {"TTL-2", "R"},
		DimRemanence:      {"CACHE-1", "R"},
		DimAnalyse:        {"ANA-3", "R-"},
		DimJournalisation: {"JOURN-1", "R+"},
		DimTransport:      {"TLS-2", "R"},
		DimMarquage:       {"MARQ-1", "R"},
	}
	for dimension, attendu := range attendus {
		o, ok := p.Option(dimension)
		if !ok {
			t.Errorf("dimension %s absente", dimension)
			continue
		}
		if o.ID != attendu[0] || o.Niveau != attendu[1] {
			t.Errorf("%s = %s (%s), attendu %s (%s)", dimension, o.ID, o.Niveau, attendu[0], attendu[1])
		}
	}
	if !p.ConformeII901 {
		t.Errorf("l'exemple du manuel doit être conforme aux minima II 901 : %v", p.EcartsII901)
	}
	if p.TailleMax != "256 Kio" || p.DureeMax != "24h" || p.DureeDefaut != "1h" {
		t.Errorf("bornes = %q / %q / %q", p.TailleMax, p.DureeMax, p.DureeDefaut)
	}
}

func TestVariantesOptions(t *testing.T) {
	cas := []struct {
		nom       string
		muter     func(m map[string]map[string]any)
		dimension string
		id        string
	}{
		{"AUTH-3 jeton", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "jeton"
			m["auth"]["ac_clients"] = ""
			m["auth"]["jetons"] = "/etc/ardoise/jetons.json"
		}, DimIdentification, "AUTH-3"},
		{"AUTH-4 declaratif", func(m map[string]map[string]any) {
			m["auth"]["mecanisme"] = "declaratif"
			m["auth"]["ac_clients"] = ""
		}, DimIdentification, "AUTH-4"},
		{"CHIF-3 motdepasse", func(m map[string]map[string]any) { m["contenu"]["chiffrement"] = "motdepasse" }, DimContenu, "CHIF-3"},
		{"RET-1 lecture unique imposée", func(m map[string]map[string]any) { m["retention"]["lecture_unique"] = "imposee" }, DimConservation, "RET-1"},
		{"RET-3 disque chiffré", func(m map[string]map[string]any) {
			m["retention"]["support"] = "disque-chiffre"
			m["retention"]["cle_magasin"] = "/etc/ardoise/magasin.cle"
		}, DimConservation, "RET-3"},
		{"TTL-1 une heure", func(m map[string]map[string]any) {
			m["retention"]["duree_max"] = "1h"
			m["retention"]["duree_defaut"] = "30m"
		}, DimDureeDeVie, "TTL-1"},
		{"TTL-3 sept jours", func(m map[string]map[string]any) { m["retention"]["duree_max"] = "168h" }, DimDureeDeVie, "TTL-3"},
		{"CACHE-2 borné", func(m map[string]map[string]any) { m["cache"]["politique"] = "borne" }, DimRemanence, "CACHE-2"},
		{"CACHE-3 libre", func(m map[string]map[string]any) { m["cache"]["politique"] = "libre" }, DimRemanence, "CACHE-3"},
		{"ANA-4 sans analyse", func(m map[string]map[string]any) { m["analyse"]["secrets_client"] = "desactive" }, DimAnalyse, "ANA-4"},
		{"ANA-2 mode analyse", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["contenu"]["chiffrement"] = "serveur"
			m["analyse"]["icap_url"] = "icap://a.interne:1344/reqmod"
		}, DimAnalyse, "ANA-2"},
		{"ANA-1 mode analyse avec règles", func(m map[string]map[string]any) {
			m["instance"]["mode"] = "analyse"
			m["contenu"]["chiffrement"] = "serveur"
			m["analyse"]["icap_url"] = "icap://a.interne:1344/reqmod"
			m["analyse"]["icap_regles"] = "/etc/ardoise/regles.yar"
		}, DimAnalyse, "ANA-1"},
		{"JOURN-2 collecteur sans chaînage", func(m map[string]map[string]any) { m["journal"]["chainage"] = false }, DimJournalisation, "JOURN-2"},
		{"JOURN-3 fichier", func(m map[string]map[string]any) {
			m["journal"]["destination"] = "fichier"
			m["journal"]["chainage"] = false
		}, DimJournalisation, "JOURN-3"},
		{"JOURN-4 aucun", func(m map[string]map[string]any) {
			m["journal"]["destination"] = "aucun"
			m["journal"]["chainage"] = false
		}, DimJournalisation, "JOURN-4"},
		{"TLS-3 en 1.2", func(m map[string]map[string]any) { m["transport"]["version_min"] = "1.2" }, DimTransport, "TLS-3"},
		{"MARQ-2 sans marquage", func(m map[string]map[string]any) { m["marquage"]["actif"] = false }, DimMarquage, "MARQ-2"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m := configComplete()
			c.muter(m)
			_, problemes, err := Analyser(enJSON(t, m))
			if err != nil {
				t.Fatal(err)
			}
			if len(problemes) != 0 {
				t.Fatalf("problèmes inattendus : %v", problemes)
			}
			inst, _, _ := Analyser(enJSON(t, m))
			p := inst.Politique()
			o, ok := p.Option(c.dimension)
			if !ok || o.ID != c.id {
				t.Fatalf("option %s = %+v, attendu %s", c.dimension, o, c.id)
			}
		})
	}
}

func TestEcartsII901(t *testing.T) {
	m := configComplete()
	m["auth"]["mecanisme"] = "declaratif"
	m["auth"]["ac_clients"] = ""
	m["retention"]["duree_max"] = "168h"
	m["contenu"]["chiffrement"] = "motdepasse"
	m["analyse"]["secrets_client"] = "desactive"
	m["journal"]["destination"] = "aucun"
	m["journal"]["chainage"] = false
	m["transport"]["version_min"] = "1.2"
	m["marquage"]["actif"] = false
	m["cache"]["politique"] = "libre"
	inst, problemes, err := Analyser(enJSON(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if len(problemes) != 0 {
		t.Fatalf("problèmes inattendus : %v", problemes)
	}
	ecarts := inst.EcartsII901()
	if len(ecarts) != 8 {
		t.Fatalf("8 écarts attendus, obtenu %d : %v", len(ecarts), ecarts)
	}
	texte := strings.Join(ecarts, "\n")
	for _, motif := range []string{"AUTH-4", "24h", "CHIF-3", "ANA-4", "JOURN-4", "TLS-3", "MARQ-2", "CACHE-3"} {
		if !strings.Contains(texte, motif) {
			t.Errorf("écart mentionnant %q attendu dans :\n%s", motif, texte)
		}
	}
	if p := inst.Politique(); p.ConformeII901 {
		t.Error("ConformeII901 devrait être faux")
	}
}
