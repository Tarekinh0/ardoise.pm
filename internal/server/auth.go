package server

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"ardoise.pm/internal/config"
)

// Mécanismes consignés dans les métadonnées d'imputabilité (ADR-005) : le
// journal (phase JOURN) reprend cette valeur telle quelle, de sorte que la
// force probante de chaque entrée soit lisible dans le journal lui-même —
// une identité « declaratif » est explicitement marquée comme non
// authentifiée et ne fonde aucune imputabilité opposable.
const (
	MecanismeCertificat = "certificat" // AUTH-1 et AUTH-2 (mTLS)
	MecanismeJeton      = "jeton"      // AUTH-3
	MecanismeDeclaratif = "declaratif" // AUTH-4 — non authentifié
)

// Identite est l'identité rattachée à une requête authentifiée. Elle circule
// dans le context.Context de la requête ; la journalisation (ADR-005) la
// consigne avec son mécanisme.
type Identite struct {
	// Utilisateur est l'identité de l'appelant : CN ou SAN du certificat
	// client, identité associée au jeton, ou valeur déclarée par le client.
	Utilisateur string
	// Hote n'est renseigné qu'en identification déclarative (AUTH-4), où le
	// client annonce aussi le poste d'où il opère.
	Hote string
	// Mecanisme vaut MecanismeCertificat, MecanismeJeton ou
	// MecanismeDeclaratif.
	Mecanisme string
}

// cleIdentite est la clé privée du contexte : seule IdentiteDepuisContexte
// permet la lecture.
type cleIdentite struct{}

// avecIdentite rattache l'identité au contexte de la requête.
func avecIdentite(ctx context.Context, id *Identite) context.Context {
	return context.WithValue(ctx, cleIdentite{}, id)
}

// IdentiteDepuisContexte restitue l'identité rattachée à la requête par le
// contrôle d'authentification. C'est le point d'appui de la journalisation
// (ADR-005) : identité et mécanisme, jamais plus. Elle est absente sur les
// routes servies avant authentification (GET /v1/politique).
func IdentiteDepuisContexte(ctx context.Context) (*Identite, bool) {
	id, ok := ctx.Value(cleIdentite{}).(*Identite)
	return id, ok
}

// reIdentifiantDeclare borne la syntaxe des identités déclarées (AUTH-4) :
// minuscules, chiffres, point, tiret, tiret bas, soulignés, 64 caractères au
// plus. Rien d'autre n'entre dans le journal.
var reIdentifiantDeclare = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

// exigerIdentite est le contrôle d'authentification du serveur (ADR-009) :
// chaque dépôt et chaque récupération doit être rattaché à une identité,
// selon le mécanisme retenu par l'instance — aucune configuration
// n'autorise l'anonymat, et aucun réglage ne désactive ce contrôle.
//
// GET /v1/politique est volontairement servi hors de ce contrôle : la
// politique est une métadonnée publique de l'instance (aucun contenu, aucune
// clé, aucun identifiant d'ardoise) et c'est elle qui annonce au client le
// mécanisme d'identification exigé — sans elle, un client ne saurait pas
// quel matériel présenter. Sous mTLS (AUTH-1/AUTH-2), la poignée de main
// TLS elle-même exige déjà un certificat vérifiable (ClientAuth =
// RequireAndVerifyClientCert) : « avant authentification » signifie ici
// avant rattachement d'une identité applicative, jamais hors TLS.
func exigerIdentite(inst *config.Instance, jetons *Jetons, suivant http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identite, err := identifier(inst, jetons, r)
		if err != nil {
			ecrireAuthRequise(w, inst.Auth.Mecanisme)
			return
		}
		suivant.ServeHTTP(w, r.WithContext(avecIdentite(r.Context(), identite)))
	})
}

// identifier applique le mécanisme de l'instance à la requête. L'erreur
// retournée ne sert qu'à la décision : rien de ce que le client a présenté
// n'est reproduit dans la réponse.
func identifier(inst *config.Instance, jetons *Jetons, r *http.Request) (*Identite, error) {
	switch inst.Auth.Mecanisme {
	case config.MecanismeMTLS, config.MecanismeMTLSMateriel:
		// AUTH-1 et AUTH-2 partagent le même contrôle serveur : la
		// contrainte du support matériel (AUTH-1) porte sur le poste
		// client et l'IGC de l'entité, pas sur l'instance. La validité du
		// certificat (chaîne jusqu'à auth.ac_clients, période de validité)
		// a déjà été vérifiée par la poignée de main TLS (crypto/x509).
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, errors.New("aucun certificat client présenté")
		}
		utilisateur, err := identiteCertificat(r.TLS.PeerCertificates[0], inst.Auth.ChampIdentite)
		if err != nil {
			return nil, err
		}
		return &Identite{Utilisateur: utilisateur, Mecanisme: MecanismeCertificat}, nil

	case config.MecanismeJeton:
		jeton, ok := jetonPorteur(r)
		if !ok {
			return nil, errors.New("aucun jeton présenté")
		}
		utilisateur, ok := jetons.Identite(jeton)
		if !ok {
			return nil, errors.New("jeton inconnu")
		}
		return &Identite{Utilisateur: utilisateur, Mecanisme: MecanismeJeton}, nil

	case config.MecanismeDeclaratif:
		utilisateur := r.Header.Get("X-Ardoise-Utilisateur")
		hote := r.Header.Get("X-Ardoise-Hote")
		if !reIdentifiantDeclare.MatchString(utilisateur) || !reIdentifiantDeclare.MatchString(hote) {
			return nil, errors.New("en-têtes d'identification déclarative absents ou invalides")
		}
		// L'identité n'est pas vérifiée : le mécanisme « declaratif » suit
		// l'entrée jusqu'au journal, qui la marquera comme telle (ADR-005).
		return &Identite{Utilisateur: utilisateur, Hote: hote, Mecanisme: MecanismeDeclaratif}, nil
	}
	// Mécanisme inconnu : la validation de configuration l'interdit avant le
	// démarrage ; par défaut, refus (jamais d'anonymat, ADR-009).
	return nil, fmt.Errorf("mécanisme d'identification « %s » inconnu", inst.Auth.Mecanisme)
}

// identiteCertificat extrait l'identité du certificat client selon
// auth.champ_identite : le CN du sujet, ou le premier SAN du type demandé.
func identiteCertificat(cert *x509.Certificate, champ string) (string, error) {
	switch champ {
	case "CN":
		if cert.Subject.CommonName != "" {
			return cert.Subject.CommonName, nil
		}
	case "SAN:email":
		if len(cert.EmailAddresses) > 0 {
			return cert.EmailAddresses[0], nil
		}
	case "SAN:dns":
		if len(cert.DNSNames) > 0 {
			return cert.DNSNames[0], nil
		}
	case "SAN:uri":
		if len(cert.URIs) > 0 {
			return cert.URIs[0].String(), nil
		}
	default:
		return "", fmt.Errorf("champ d'identité « %s » inconnu", champ)
	}
	return "", fmt.Errorf("certificat client sans identité dans le champ « %s »", champ)
}

// jetonPorteur extrait le jeton de l'en-tête « Authorization: Bearer … ».
func jetonPorteur(r *http.Request) ([]byte, bool) {
	const prefixe = "Bearer "
	autorisation := r.Header.Get("Authorization")
	if len(autorisation) <= len(prefixe) || autorisation[:len(prefixe)] != prefixe {
		return nil, false
	}
	return []byte(autorisation[len(prefixe):]), true
}

// ecrireAuthRequise émet le refus 401 (code de retour client 6). Le message
// guide le client vers le matériel attendu sans rien restituer de ce qui a
// été présenté.
func ecrireAuthRequise(w http.ResponseWriter, mecanisme string) {
	message := "authentification requise"
	switch mecanisme {
	case config.MecanismeMTLS, config.MecanismeMTLSMateriel:
		message = "certificat client requis : l'instance exige une authentification par certificat"
	case config.MecanismeJeton:
		// WWW-Authenticate accompagne tout 401 de jeton (RFC 6750).
		w.Header().Set("WWW-Authenticate", `Bearer realm="ardoise"`)
		message = "jeton requis ou refusé : présentez le jeton délivré par le service d'identité (« Authorization: Bearer … »)"
	case config.MecanismeDeclaratif:
		message = "identification déclarative requise : en-têtes « X-Ardoise-Utilisateur » et « X-Ardoise-Hote » absents ou invalides"
	}
	ecrireErreur(w, http.StatusUnauthorized, "authentification_requise", message)
}
