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
        ardoise get --mots

Récupère un contenu et l'écrit sur la sortie standard, sans ajout ni mise en
forme. Un tiret (« - ») fait lire l'identifiant sur l'entrée standard, afin
de ne pas l'exposer aux autres utilisateurs de la machine.
Avec --mots, 5 mots mnémoniques sont saisis interactivement (CHIF-5).

Options de récupération :
  -o, --sortie CHEMIN            écrit le contenu dans un fichier
  -n, --sans-cache               n'utilise pas le cache local et n'y écrit pas
      --cache-seul               sert exclusivement depuis le cache local
      --verifier-empreinte EMP   compare l'empreinte du chiffré reçu à la
                                 valeur fournie et refuse en cas d'écart
      --mots                     récupère une ardoise par 5 mots mnémoniques
                                 (CHIF-5, saisie interactive obligatoire)
      --argument                 lit l'identifiant depuis la ligne de commande
                                 (par défaut, il est lu sur stdin)
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
	var sansCache, cacheSeul, mots, argument bool
	fs.StringVar(&cheminSortie, "sortie", "", "")
	fs.StringVar(&cheminSortie, "o", "", "")
	fs.BoolVar(&sansCache, "sans-cache", false, "")
	fs.BoolVar(&sansCache, "n", false, "")
	fs.BoolVar(&cacheSeul, "cache-seul", false, "")
	fs.StringVar(&empreinte, "verifier-empreinte", "", "")
	fs.BoolVar(&mots, "mots", false, "")
	fs.BoolVar(&argument, "argument", false, "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideGet)
		return nil
	}
	if sansCache && cacheSeul {
		return erreurUsage("« --sans-cache » et « --cache-seul » sont exclusifs")
	}
	if empreinte != "" && !reEmpreinte.MatchString(empreinte) {
		return erreurUsage("« --verifier-empreinte » : empreinte invalide (attendu : 64 caractères hexadécimaux, préfixe « sha256: » admis)")
	}

	// --mots : saisie interactive, ignore IDENTIFIANT
	if mots {
		return cmdGetMots(ctx, &com, &auth, cheminSortie, empreinte, sansCache, cacheSeul)
	}

	if fs.NArg() == 0 {
		return erreurUsage("IDENTIFIANT requis (ou « - » pour le lire sur l'entrée standard)")
	}
	if err := verifierPositionnels(fs, 1, "ardoise get [OPTIONS] IDENTIFIANT"); err != nil {
		return err
	}

	brut := fs.Arg(0)
	// C2 : par défaut, lire l'identifiant depuis stdin, pas argv.
	// « --argument » restaure l'ancien comportement.
	if !argument {
		// L'identifiant est lu sur stdin pour ne pas apparaître
		// dans les arguments du processus ni l'historique (docs/man.md,
		// SÉCURITÉ).
		ligne, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && ligne == "" {
			return erreurUsage("aucun identifiant sur l'entrée standard (utilisez « --argument » pour passer l'identifiant en argument)")
		}
		brut = ligne
	} else if brut == "-" {
		ligne, err := bufio.NewReader(os.Stdin).ReadString('\n')
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

	// Récupération
	var reponse *client.ReponseArdoise
	if cacheSeul {
		cache, errCache := cacheDuPoste(ctx)
		if errCache != nil {
			return errCache
		}
		entree, errLecture := cache.Lire(id)
		if errLecture != nil {
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

	// Vérification empreinte
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
		clair, err = dechiffrerMultiDest(ctx, reponse.Chiffre)
		if err != nil {
			return err
		}
	} else {
		if crypto.BesoinMots(schema) {
			return erreurUsage("ce contenu a été chiffré avec des mots mnémoniques (CHIF-5) : utilisez « ardoise get --mots »")
		}
		if crypto.BesoinCle(schema) && cle == nil {
			return erreurUsage("identifiant incomplet : ce contenu exige le matériel de clé après « # »")
		}
		clair, err = crypto.Dechiffrer(reponse.Chiffre, cle)
		if err != nil {
			return Erreurf(CodeErreur, "%v", err)
		}
	}

	// Sortie structurée
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

// cmdGetMots traite la récupération par mots mnémoniques (CHIF-5).
func cmdGetMots(ctx *Contexte, com *optionsCommunes, auth *optionsAuthClient, cheminSortie, empreinte string, sansCache, cacheSeul bool) error {
	motsSaisis, err := ctx.LireMots(5)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}

	graine := crypto.DeriverGraine(motsSaisis)
	defer crypto.Effacer(graine)

	id, err := crypto.DeriverIDDepuisGraine(graine)
	if err != nil {
		return Erreurf(CodeErreur, "dérivation de l'identifiant : %v", err)
	}

	// Récupération
	var reponse *client.ReponseArdoise
	if cacheSeul {
		cache, errCache := cacheDuPoste(ctx)
		if errCache != nil {
			return errCache
		}
		entree, errLecture := cache.Lire(id)
		if errLecture != nil {
			return Erreurf(CodeIntrouvable, "%v", errLecture)
		}
		reponse = reponseDepuisCache(entree)
	} else {
		cl, _, errClient := preparerClient(ctx, com, auth)
		if errClient != nil {
			return errClient
		}
		reponse, err = cl.Recuperer(id)
		switch {
		case err == nil:
			if !sansCache {
				ecrireAuCache(nouvelleSortie(ctx, com), cl, ctx, id, reponse)
			}
		default:
			if !sansCache && estIntrouvable(err) {
				if cache, errCache := cacheDuPoste(ctx); errCache == nil {
					if entree, errLecture := cache.Lire(id); errLecture == nil {
						reponse = reponseDepuisCache(entree)
					}
				}
			}
			if reponse == nil {
				return traduireErreurClient(err)
			}
		}
	}

	// Vérification empreinte
	empreinteLocale := crypto.Empreinte(reponse.Chiffre)
	if !crypto.EmpreintesEgales(empreinteLocale, reponse.Empreinte) {
		return Erreurf(CodeErreur, "empreinte incohérente : le contenu reçu ne correspond pas à l'empreinte annoncée par l'instance")
	}
	if empreinte != "" && !crypto.EmpreintesEgales(empreinteLocale, empreinte) {
		return Erreurf(CodeErreur, "empreinte incohérente : le contenu reçu ne correspond pas à la valeur de « --verifier-empreinte »")
	}

	// Vérification du schéma : le chiffré doit être en VersionMots (0x06)
	schema, err := crypto.Schema(reponse.Chiffre)
	if err != nil {
		return Erreurf(CodeErreur, "contenu inexploitable : %v", err)
	}
	if !crypto.BesoinMots(schema) {
		return erreurUsage("ce contenu n'a pas été chiffré avec des mots mnémoniques (CHIF-5)")
	}

	// Déchiffrement CHIF-5
	clair, err := dechiffrerMots(reponse.Chiffre, motsSaisis)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}
	defer crypto.Effacer(clair)

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

// reponseDepuisCache reconstitue la réponse d'une entrée du cache local.
func reponseDepuisCache(entree *client.EntreeCache) *client.ReponseArdoise {
	return &client.ReponseArdoise{
		Chiffre:   entree.Chiffre,
		Empreinte: entree.Empreinte,
		Echeance:  entree.Echeance,
		Marquage:  entree.Marquage,
	}
}

// ecrireAuCache conserve le chiffré reçu lorsque la politique de l'instance
// l'autorise.
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

// estIntrouvable reconnaît la réponse du code 5 de l'instance (404/410).
func estIntrouvable(err error) bool {
	e, ok := err.(*client.ErreurAPI)
	return ok && (e.Statut == 404 || e.Statut == 410)
}

// dechiffrerMultiDest ouvre un chiffré CHIF-MD avec la clé privée du poste.
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
	clair, err := crypto.DechiffrerMultiDest(chiffre, "", clePrivee)
	if err != nil {
		return nil, Erreurf(CodeErreur, "%v", err)
	}
	return clair, nil
}

// ecrireFichierPrive écrit le clair dans un fichier aux droits 0600.
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
