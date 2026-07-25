package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Client est la configuration du poste client (docs/man.md, « FICHIER DE
// CONFIGURATION CLIENT », amendé : client.json). Les clés pkcs11 et jeton
// complètent le fichier du manuel afin de couvrir les mêmes réglages que les
// variables d'environnement ARDOISE_PKCS11 et ARDOISE_JETON ; annuaire et
// cle_privee_ardoise portent le chiffrement multi-destinataires (CHIF-MD,
// ADR-014 cas a) :
//
//	Clé                 Variable              Rôle
//	───────────────────────────────────────────────────────────────────────
//	annuaire            ARDOISE_ANNUAIRE      annuaire de clés publiques
//	                                          X25519 (JSON : identité →
//	                                          clé publique base64)
//	cle_privee_ardoise  ARDOISE_CLE_PRIVEE    clé privée X25519 du poste
//	                                          (fichier 0600, base64 ou
//	                                          hexadécimal, 32 octets)
type Client struct {
	Endpoint         string `json:"endpoint"`
	AC               string `json:"ac"`
	Certificat       string `json:"certificat"`
	Cle              string `json:"cle"`
	PKCS11           string `json:"pkcs11"`
	Jeton            string `json:"jeton"`
	Cache            string `json:"cache"`
	Annuaire         string `json:"annuaire"`
	ClePriveeArdoise string `json:"cle_privee_ardoise"`
}

// variablesClient relie chaque variable d'environnement du manuel au champ
// de configuration qu'elle surcharge.
var variablesClient = []struct {
	variable string
	champ    func(*Client) *string
}{
	{"ARDOISE_ENDPOINT", func(c *Client) *string { return &c.Endpoint }},
	{"ARDOISE_AC", func(c *Client) *string { return &c.AC }},
	{"ARDOISE_CERTIFICAT", func(c *Client) *string { return &c.Certificat }},
	{"ARDOISE_CLE", func(c *Client) *string { return &c.Cle }},
	{"ARDOISE_PKCS11", func(c *Client) *string { return &c.PKCS11 }},
	{"ARDOISE_JETON", func(c *Client) *string { return &c.Jeton }},
	{"ARDOISE_CACHE", func(c *Client) *string { return &c.Cache }},
	{"ARDOISE_ANNUAIRE", func(c *Client) *string { return &c.Annuaire }},
	{"ARDOISE_CLE_PRIVEE", func(c *Client) *string { return &c.ClePriveeArdoise }},
}

// ChargerClient charge la configuration client. Les chemins sont lus dans
// l'ordre croissant de préséance (le poste, puis l'utilisateur) ; un fichier
// absent est ignoré, un fichier illisible ou non strictement conforme est une
// erreur. Les variables d'environnement l'emportent sur les fichiers ; les
// options de ligne de commande, traitées par l'appelant, l'emportent sur tout.
func ChargerClient(chemins []string, getenv func(string) string) (*Client, error) {
	c := &Client{}
	for _, chemin := range chemins {
		donnees, err := os.ReadFile(chemin)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("lecture de la configuration client %s : %w", chemin, err)
		}
		var fichier Client
		if err := decoderStrict(donnees, &fichier); err != nil {
			return nil, fmt.Errorf("configuration client %s invalide : %v", chemin, err)
		}
		c.fusionner(&fichier)
	}
	if getenv != nil {
		for _, v := range variablesClient {
			if valeur := getenv(v.variable); valeur != "" {
				*v.champ(c) = valeur
			}
		}
	}
	return c, nil
}

// fusionner reporte dans c les champs non vides d'autre.
func (c *Client) fusionner(autre *Client) {
	for _, v := range variablesClient {
		if valeur := *v.champ(autre); valeur != "" {
			*v.champ(c) = valeur
		}
	}
}
