package cli

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"strings"

	"ardoise.pm/internal/client"
	"ardoise.pm/internal/config"
)

// messagePKCS11 : le support matériel exige un module PKCS#11 natif,
// incompatible avec la contrainte de binaire statique sans cgo du produit.
// L'option est acceptée pour que le manuel reste exact, mais refusée avec
// une explication plutôt qu'ignorée en silence.
const messagePKCS11 = "PKCS#11 non pris en charge dans cette version (nécessite cgo, incompatible binaire statique — voir dossier de risques)"

// preparerClient résout l'instance cible (option --endpoint, variable
// ARDOISE_ENDPOINT, configuration client) et le matériel d'authentification
// (certificat client, jeton, identité déclarée), puis construit le client
// d'API. Jamais d'InsecureSkipVerify, en aucune circonstance.
func preparerClient(ctx *Contexte, com *optionsCommunes, auth *optionsAuthClient) (*client.Client, error) {
	configClient, err := config.ChargerClient(ctx.CheminsConfigClient, ctx.Getenv)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}

	endpoint := com.endpoint
	if endpoint == "" {
		endpoint = configClient.Endpoint
	}
	if endpoint == "" {
		return nil, erreurUsage("aucune instance indiquée : utilisez « --endpoint », la variable ARDOISE_ENDPOINT ou la configuration client")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, erreurUsage("endpoint « %s » invalide (attendu : https://hôte:port)", endpoint)
	}
	if u.Scheme != "https" {
		return nil, erreurUsage("endpoint « %s » refusé : seul le schéma https est pris en charge, les flux sont toujours protégés par TLS", endpoint)
	}

	if premierNonVide(auth.pkcs11, configClient.PKCS11) != "" {
		return nil, Erreurf(CodeErreur, "%s", messagePKCS11)
	}

	ac := premierNonVide(auth.ac, configClient.AC)
	certificat, cle := auth.certificat, auth.cle
	if certificat == "" && cle == "" {
		certificat, cle = configClient.Certificat, configClient.Cle
	}
	configTLS, err := configTLSClient(ac, certificat, cle)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	cl := client.Nouveau(endpoint, configTLS)

	cheminJeton := premierNonVide(auth.jeton, configClient.Jeton)
	if cheminJeton != "" {
		jeton, err := lireJeton(ctx, cheminJeton)
		if err != nil {
			return nil, err
		}
		cl.DefinirJeton(jeton)
	}

	// Identité déclarée (AUTH-4) : préparée seulement si aucun autre
	// matériel n'est fourni — le client ne l'enverra que si la politique de
	// l'instance retient l'identification déclarative.
	if certificat == "" && cheminJeton == "" {
		cl.DeclarerIdentite(identiteLocale(ctx))
	}
	return cl, nil
}

// premierNonVide retourne la première valeur non vide : l'option de ligne
// de commande l'emporte sur la configuration (elle-même déjà surchargée par
// les variables d'environnement).
func premierNonVide(valeurs ...string) string {
	for _, v := range valeurs {
		if v != "" {
			return v
		}
	}
	return ""
}

// lireJeton lit le fichier de jeton (AUTH-3) : le jeton lui-même ne passe
// jamais en argument de ligne de commande (docs/man.md). Des droits plus
// larges que 0600 valent un avertissement — non supprimable par
// « --silencieux », comme tout signalement de sécurité — mais pas un refus :
// le poste appartient à l'utilisateur, pas au produit.
func lireJeton(ctx *Contexte, chemin string) ([]byte, error) {
	infos, err := os.Stat(chemin)
	if err != nil {
		return nil, Erreurf(CodeErreur, "fichier de jeton : %v", err)
	}
	if mode := infos.Mode().Perm(); mode&0o077 != 0 {
		fmt.Fprintf(ctx.Stderr, "ardoise : avertissement : le fichier de jeton %s est accessible à d'autres utilisateurs (droits %04o, 0600 recommandé)\n", chemin, mode)
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, Erreurf(CodeErreur, "fichier de jeton : %v", err)
	}
	jeton := bytes.TrimSpace(donnees)
	if len(jeton) == 0 {
		return nil, Erreurf(CodeErreur, "fichier de jeton %s vide", chemin)
	}
	return jeton, nil
}

// identiteLocale détermine l'identité annoncée du poste pour
// l'identification déclarative (AUTH-4) : l'utilisateur courant (os/user,
// sinon la variable USER) et le nom d'hôte. Les valeurs sont normalisées à
// la syntaxe admise par le serveur ([a-z0-9._-], 64 caractères au plus) —
// l'identité étant déclarative et non vérifiée, cette normalisation
// n'affaiblit rien.
func identiteLocale(ctx *Contexte) (utilisateur, hote string) {
	if u, err := user.Current(); err == nil {
		utilisateur = u.Username
	}
	if utilisateur == "" && ctx.Getenv != nil {
		utilisateur = ctx.Getenv("USER")
	}
	hote, _ = os.Hostname()
	return normaliserIdentifiant(utilisateur), normaliserIdentifiant(hote)
}

// normaliserIdentifiant abaisse la casse et ne conserve que les caractères
// admis par la syntaxe déclarative, bornés à 64.
func normaliserIdentifiant(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			if b.Len() == 64 {
				break
			}
		}
	}
	return b.String()
}

// traduireErreurClient traduit une erreur du paquet client en Erreur du
// manuel : statut HTTP → code de retour (401/403→6, 404/410→5, 413→8,
// 422→3, 451→7), refus de certificat client → 6, injoignable → 9.
func traduireErreurClient(err error) error {
	switch e := err.(type) {
	case *client.ErreurAPI:
		return Erreurf(CodePourStatutHTTP(e.Statut), "%s", e.Error())
	case *client.ErreurCertificatClient:
		return Erreurf(CodeAuthRefusee, "%s", e.Error())
	case *client.ErreurReseau:
		return Erreurf(CodeInjoignable, "%s", e.Error())
	default:
		return Erreurf(CodeErreur, "%v", err)
	}
}
