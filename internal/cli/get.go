package cli

import (
	"bufio"
	"os"
	"regexp"

	"ardoise.pm/internal/crypto"
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
	if cacheSeul {
		return Erreurf(CodeErreur, "le cache local n'est pas disponible dans cette version")
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

	cl, err := preparerClient(ctx, &com, &auth)
	if err != nil {
		return err
	}
	reponse, err := cl.Recuperer(id)
	if err != nil {
		return traduireErreurClient(err)
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

	clair, err := crypto.Dechiffrer(reponse.Chiffre, cle, motDePasse)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}

	// Restitution brute, sans ajout ni mise en forme, composable en shell
	// (EF-2). L'application du marquage en tête du contenu restitué
	// (MARQ-1, champs reponse.Marquage) arrive avec internal/marquage.
	if cheminSortie != "" {
		if err := ecrireFichierPrive(cheminSortie, clair); err != nil {
			return Erreurf(CodeErreur, "écriture de « %s » : %v", cheminSortie, err)
		}
		return nil
	}
	if _, err := ctx.Stdout.Write(clair); err != nil {
		return Erreurf(CodeErreur, "écriture de la sortie : %v", err)
	}
	return nil
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
