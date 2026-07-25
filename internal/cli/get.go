package cli

import (
	"bufio"
	"os"
	"regexp"

	"ardoise.pm/internal/client"
	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/marquage"
)

// reEmpreinte : empreinte SHA-256 hexadécimale, préfixe « sha256: » admis.
var reEmpreinte = regexp.MustCompile(`^(sha256:)?[0-9a-fA-F]{64}$`)

const aideGet = `usage : ardoise get [OPTIONS] IDENTIFIANT
        ardoise get [OPTIONS] -

Récupère un contenu et l'écrit sur la sortie standard, sans ajout ni mise en
forme. Un tiret (« - ») fait lire l'identifiant sur l'entrée standard, afin
de ne pas l'exposer aux autres utilisateurs de la machine.

Options de récupération :
  -o, --sortie CHEMIN            écrit le contenu dans un fichier
  -n, --sans-cache               n'utilise pas le cache local et n'y écrit pas
      --cache-seul               sert exclusivement depuis le cache local
      --verifier-empreinte EMP   compare l'empreinte du chiffré reçu à la
                                 valeur fournie et refuse en cas d'écart
` + aideCommunes + aideAuthClient

// cmdGet récupère une ardoise : appel de l'instance avec le seul
// identifiant serveur (le fragment de clé ne part jamais), vérification de
// l'empreinte du chiffré, déchiffrement local, restitution brute.
func cmdGet(ctx *Contexte, args []string) error {
	fs := nouveauFS("get")
	var com optionsCommunes
	com.enregistrer(fs)
	var auth optionsAuthClient
	auth.enregistrer(fs)
	var cheminSortie, empreinte string
	var sansCache, cacheSeul bool
	fs.StringVar(&cheminSortie, "sortie", "", "")
	fs.StringVar(&cheminSortie, "o", "", "")
	fs.BoolVar(&sansCache, "sans-cache", false, "")
	fs.BoolVar(&sansCache, "n", false, "")
	fs.BoolVar(&cacheSeul, "cache-seul", false, "")
	fs.StringVar(&empreinte, "verifier-empreinte", "", "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideGet)
		return nil
	}
	if fs.NArg() == 0 {
		return erreurUsage("IDENTIFIANT requis (ou « - » pour le lire sur l'entrée standard)")
	}
	if err := verifierPositionnels(fs, 1, "ardoise get [OPTIONS] IDENTIFIANT"); err != nil {
		return err
	}
	if sansCache && cacheSeul {
		return erreurUsage("« --sans-cache » et « --cache-seul » sont exclusifs")
	}
	if empreinte != "" && !reEmpreinte.MatchString(empreinte) {
		return erreurUsage("« --verifier-empreinte » : empreinte invalide (attendu : 64 caractères hexadécimaux, préfixe « sha256: » admis)")
	}

	brut := fs.Arg(0)
	if brut == "-" {
		// L'identifiant est lu sur l'entrée standard pour ne pas apparaître
		// dans les arguments du processus ni l'historique (docs/man.md,
		// SÉCURITÉ).
		ligne, err := bufio.NewReader(ctx.Stdin).ReadString('\n')
		if err != nil && ligne == "" {
			return erreurUsage("aucun identifiant sur l'entrée standard")
		}
		brut = ligne
	}
	id, cle, err := crypto.ParseIdentifiant(brut)
	if err != nil {
		return erreurUsage("%v", err)
	}
	defer crypto.Effacer(cle)

	s := nouvelleSortie(ctx, &com)

	// Récupération : l'instance par défaut, le cache local seul avec
	// « --cache-seul », ni lu ni écrit avec « --sans-cache » (ADR-013).
	var reponse *client.ReponseArdoise
	if cacheSeul {
		// « --cache-seul » : aucun contact avec l'instance. La politique
		// consignée dans l'entrée à l'écriture gouverne la lecture (une
		// entrée « borne » échue est détruite, jamais servie) : hors ligne,
		// le client n'excède pas ce que l'instance avait accordé.
		cache, errCache := cacheDuPoste(ctx)
		if errCache != nil {
			return errCache
		}
		entree, errLecture := cache.Lire(id)
		if errLecture != nil {
			// Même sémantique que le code 5 du serveur : absente, expirée
			// ou jamais mise en cache, rien n'est distinguable.
			return Erreurf(CodeIntrouvable, "%v", errLecture)
		}
		reponse = reponseDepuisCache(entree)
	} else {
		cl, _, errClient := preparerClient(ctx, &com, &auth)
		if errClient != nil {
			return errClient
		}
		reponse, err = cl.Recuperer(id)
		switch {
		case err == nil:
			if !sansCache {
				ecrireAuCache(s, cl, ctx, id, reponse)
			}
		default:
			// Repli sur le cache local, uniquement lorsque l'instance
			// répond code 5 : une ardoise à lecture unique déjà consommée
			// reste rejouable depuis le poste — c'est la raison d'être du
			// cache (ADR-013). Tout autre échec (réseau, refus) est rendu
			// tel quel ; « --sans-cache » désactive aussi ce repli.
			if !sansCache && estIntrouvable(err) {
				if cache, errCache := cacheDuPoste(ctx); errCache == nil {
					if entree, errLecture := cache.Lire(id); errLecture == nil {
						s.infof("Instance sans cette ardoise : contenu servi depuis le cache local")
						reponse = reponseDepuisCache(entree)
					}
				}
			}
			if reponse == nil {
				return traduireErreurClient(err)
			}
		}
	}

	// Le chiffré reçu doit porter l'empreinte annoncée par l'instance, et
	// celle fournie par l'utilisateur le cas échéant : tout écart est un
	// refus, jamais un avertissement (docs/dat.md §4.3, annexe B).
	empreinteLocale := crypto.Empreinte(reponse.Chiffre)
	if !crypto.EmpreintesEgales(empreinteLocale, reponse.Empreinte) {
		return Erreurf(CodeErreur, "empreinte incohérente : le contenu reçu ne correspond pas à l'empreinte annoncée par l'instance")
	}
	if empreinte != "" && !crypto.EmpreintesEgales(empreinteLocale, empreinte) {
		return Erreurf(CodeErreur, "empreinte incohérente : le contenu reçu ne correspond pas à la valeur de « --verifier-empreinte »")
	}

	schema, err := crypto.Schema(reponse.Chiffre)
	if err != nil {
		return Erreurf(CodeErreur, "contenu inexploitable : %v", err)
	}
	var clair []byte
	if crypto.EstMultiDest(schema) {
		// CHIF-MD : l'ouverture exige la clé privée X25519 du poste
		// (cle_privee_ardoise, ARDOISE_CLE_PRIVEE) — l'identifiant ne porte
		// qu'une sentinelle, jamais une clé (multidest.go).
		clair, err = dechiffrerMultiDest(ctx, reponse.Chiffre)
		if err != nil {
			return err
		}
	} else {
		if crypto.BesoinCle(schema) && cle == nil {
			return erreurUsage("identifiant incomplet : ce contenu exige le matériel de clé après « # »")
		}
		var motDePasse []byte
		if crypto.BesoinMotDePasse(schema) {
			if ctx.LireMotDePasse == nil {
				return Erreurf(CodeErreur, "aucun terminal disponible pour saisir le mot de passe exigé par ce contenu")
			}
			motDePasse, err = ctx.LireMotDePasse("Mot de passe : ")
			if err != nil {
				return Erreurf(CodeErreur, "%v", err)
			}
		}
		defer crypto.Effacer(motDePasse)

		clair, err = crypto.Dechiffrer(reponse.Chiffre, cle, motDePasse)
		if err != nil {
			return Erreurf(CodeErreur, "%v", err)
		}
	}

	// Sortie structurée : le marquage voyage dans des champs distincts et
	// le contenu reste vierge — c'est le script appelant qui décide de la
	// présentation (docs/man.md, « --json »).
	if com.json {
		return ecrireJSONSortie(ctx.Stdout, struct {
			Contenu   string `json:"contenu"`
			Empreinte string `json:"empreinte"`
			Echeance  string `json:"echeance"`
			Marquage  struct {
				Actif      bool   `json:"actif"`
				Libelle    string `json:"libelle,omitempty"`
				Complement string `json:"complement,omitempty"`
			} `json:"marquage"`
		}{
			// Limitation documentée (docs/dat.md A.3-2, registre R-002) :
			// la conversion []byte → string pour la sortie JSON crée une
			// copie immuable du contenu déchiffré qui ne peut pas être
			// effacée avant le ramasse-miettes. L'appel defer crypto.Effacer
			// ne porte pas sur cette copie.
			Contenu:   string(clair),
			Empreinte: reponse.Empreinte,
			Echeance:  reponse.Echeance,
			Marquage: struct {
				Actif      bool   `json:"actif"`
				Libelle    string `json:"libelle,omitempty"`
				Complement string `json:"complement,omitempty"`
			}{reponse.Marquage.Actif, reponse.Marquage.Libelle, reponse.Marquage.Complement},
		})
	}

	// Restitution brute, sans mise en forme, composable en shell (EF-2) —
	// au seul ajout près du marquage de sensibilité lorsque l'instance
	// l'impose (MARQ-1, ES-11) : « === LIBELLE[ — complément] === » en tête
	// du contenu restitué, y compris vers un fichier. MARQ-2 : rien.
	restitution := clair
	if reponse.Marquage.Actif {
		restitution = marquage.Appliquer(reponse.Marquage.Libelle, reponse.Marquage.Complement, clair)
	}
	if cheminSortie != "" {
		if err := ecrireFichierPrive(cheminSortie, restitution); err != nil {
			return Erreurf(CodeErreur, "écriture de « %s » : %v", cheminSortie, err)
		}
		return nil
	}
	if _, err := ctx.Stdout.Write(restitution); err != nil {
		return Erreurf(CodeErreur, "écriture de la sortie : %v", err)
	}
	return nil
}

// reponseDepuisCache reconstitue la réponse d'une entrée du cache local :
// le chiffré tel que reçu de l'instance et les métadonnées du fichier
// d'accompagnement — l'empreinte y est vérifiée par l'appelant comme pour
// une réponse d'instance.
func reponseDepuisCache(entree *client.EntreeCache) *client.ReponseArdoise {
	return &client.ReponseArdoise{
		Chiffre:   entree.Chiffre,
		Empreinte: entree.Empreinte,
		Echeance:  entree.Echeance,
		Marquage:  entree.Marquage,
	}
}

// ecrireAuCache conserve le chiffré reçu lorsque la politique de l'instance
// l'autorise (« borne » ou « libre », ADR-013) : le client ne décide
// jamais seul — sous « interdit », rien n'est écrit. Un échec d'écriture
// est signalé, jamais bloquant : le contenu vient d'être servi.
func ecrireAuCache(s *sortie, cl *client.Client, ctx *Contexte, id string, reponse *client.ReponseArdoise) {
	politique, err := cl.Politique()
	if err != nil {
		return
	}
	switch politique.CachePolitique {
	case client.CacheBorne, client.CacheLibre:
	default:
		return
	}
	cache, err := cacheDuPoste(ctx)
	if err != nil {
		return
	}
	if err := cache.Ecrire(id, politique.CachePolitique, reponse); err != nil {
		s.infof("ardoise : avertissement : écriture au cache local impossible : %v", err)
	}
}

// estIntrouvable reconnaît la réponse du code 5 de l'instance (404/410) :
// la seule qui autorise le repli sur le cache local.
func estIntrouvable(err error) bool {
	e, ok := err.(*client.ErreurAPI)
	return ok && (e.Statut == 404 || e.Statut == 410)
}

// dechiffrerMultiDest ouvre un chiffré CHIF-MD avec la clé privée du poste,
// résolue depuis la configuration client (cle_privee_ardoise) ou la
// variable ARDOISE_CLE_PRIVEE. Le matériel est effacé après usage.
func dechiffrerMultiDest(ctx *Contexte, chiffre []byte) ([]byte, error) {
	configClient, err := config.ChargerClient(ctx.CheminsConfigClient, ctx.Getenv)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	if configClient.ClePriveeArdoise == "" {
		return nil, Erreurf(CodeErreur,
			"contenu chiffré pour des destinataires désignés : renseignez la clé privée du poste (clé « cle_privee_ardoise » ou ARDOISE_CLE_PRIVEE — voir « ardoise cle --generer »)")
	}
	clePrivee, err := clePriveeDestinataire(configClient.ClePriveeArdoise)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	defer crypto.Effacer(clePrivee)
	// L'identité du poste n'est pas connue du client avec certitude : chaque
	// enveloppe est essayée, la possession de la clé privée étant ce qui
	// ouvre réellement (multidest.go — l'empreinte d'identité n'est qu'un
	// index).
	clair, err := crypto.DechiffrerMultiDest(chiffre, "", clePrivee)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	return clair, nil
}

// ecrireFichierPrive écrit le clair dans un fichier aux droits 0600 :
// le contenu restitué n'appartient qu'à son destinataire.
func ecrireFichierPrive(chemin string, donnees []byte) error {
	f, err := os.OpenFile(chemin, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(donnees); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
