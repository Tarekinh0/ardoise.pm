package secrets

import (
	"strings"
	"testing"
)

// jetonTest est un authentifiant factice à préfixe GitHub (36 caractères
// après « ghp_ »), jamais un vrai secret.
const jetonTest = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

const clePriveeTest = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7bq7s8H1xkqXBspKlH+TP6lqcVimapKMhABiceUwXBTAGiCd
MIIEpAIBAAKCAQEA7bq7s8H1xkqXBspKlH+TP6lqcVimapKMhABiceUwXBTAGiCd
-----END RSA PRIVATE KEY-----`

func TestDetecterTypesEtLignes(t *testing.T) {
	cas := []struct {
		nom     string
		contenu string
		type_   string
		ligne   int
	}{
		{"préfixe connu en ligne 1", jetonTest, TypeSecret, 1},
		{"préfixe connu en ligne 3", "ligne1\nligne2\ntoken=" + jetonTest + "\n", TypeSecret, 3},
		{"clé privée PEM", "avant\n" + clePriveeTest + "\n", TypeClePrivee, 2},
		{"JWT structurel", "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.YWJjZGVmZ2hpamtsbW5vcA\n", TypeJWT, 1},
		{"AKIA AWS", "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n", TypeSecret, 1},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			detections := Detecter([]byte(c.contenu))
			if len(detections) == 0 {
				t.Fatal("aucune détection")
			}
			trouvee := false
			for _, d := range detections {
				if d.Type == c.type_ && d.Ligne == c.ligne {
					trouvee = true
				}
			}
			if !trouvee {
				t.Errorf("aucune détection {type %s, ligne %d} dans %v", c.type_, c.ligne, detections)
			}
		})
	}
}

func TestDetecterNegatifs(t *testing.T) {
	cas := []struct {
		nom     string
		contenu string
	}{
		{"vide", ""},
		{"texte ordinaire", "extrait de journal\nnginx: GET /sante 200\n"},
		{"UUID (faux positif connu)", "request_id=550e8400-e29b-41d4-a716-446655440000 token ok\n"},
		{"empreinte SHA-256 (faux positif connu)", "secret hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if detections := Detecter([]byte(c.contenu)); len(detections) != 0 {
				t.Errorf("détections inattendues : %v", detections)
			}
		})
	}
}

func TestDetecterExpurge(t *testing.T) {
	// L'alerte ne reproduit jamais le secret : quatre caractères puis « … ».
	contenu := "token=" + jetonTest + "\n"
	detections := Detecter([]byte(contenu))
	if len(detections) == 0 {
		t.Fatal("aucune détection")
	}
	for _, d := range detections {
		if d.Extrait != "ghp_…" {
			t.Errorf("extrait = %q, attendu %q", d.Extrait, "ghp_…")
		}
		if strings.Contains(d.Extrait, jetonTest[4:]) {
			t.Error("l'extrait reproduit le secret au-delà du préfixe")
		}
	}
}

// TestDetecterAucuneFuiteDuSecret vérifie l'invariant central : aucun champ
// d'aucune détection ne contient le corps du secret détecté.
func TestDetecterAucuneFuiteDuSecret(t *testing.T) {
	corpsSecret := jetonTest[4:] // le corps après le préfixe
	detections := Detecter([]byte("deploy: " + jetonTest + "\n"))
	if len(detections) == 0 {
		t.Fatal("aucune détection")
	}
	for _, d := range detections {
		for nom, champ := range map[string]string{"Type": d.Type, "Extrait": d.Extrait} {
			if strings.Contains(champ, corpsSecret) {
				t.Errorf("le champ %s contient le secret", nom)
			}
		}
	}
}

func TestDetecterGrosContenu(t *testing.T) {
	// La borne du moteur est fixée à la taille du contenu : un contenu plus
	// grand que le défaut de 1 Mio reste balayé.
	gros := strings.Repeat("ligne de remplissage sans rien de sensible\n", 30000) + "token=" + jetonTest + "\n"
	if len(gros) <= DefaultMaxInputBytes {
		t.Fatalf("le cas doit dépasser %d octets", DefaultMaxInputBytes)
	}
	detections := Detecter([]byte(gros))
	if len(detections) == 0 {
		t.Fatal("aucune détection dans le gros contenu")
	}
}
