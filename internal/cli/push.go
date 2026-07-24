package cli

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"ardoise.pm/internal/client"
	"ardoise.pm/internal/config"
	"ardoise.pm/internal/crypto"
)

// reDestinataire : identité individuelle (« alice.durand ») ou groupe de
// l'annuaire préfixé d'une arobase (« @equipe-reseau »).
var reDestinataire = regexp.MustCompile(`^@?[A-Za-z0-9][A-Za-z0-9._-]*$`)

const aidePush = `usage : ardoise [push] [OPTIONS] [FICHIER]

Dépose un contenu et affiche l'identifiant sur la sortie standard.
Le contenu est lu sur l'entrée standard, ou dans FICHIER s'il est fourni.
Commande par défaut lorsque l'entrée standard est redirigée.

Options de dépôt :
  -t, --duree DURÉE        durée de vie (30m, 2h, 24h), bornée par l'instance
  -b, --lecture-unique     détruit le contenu dès sa première récupération
  -p, --mot-de-passe       demande un mot de passe au terminal (jamais en
                           argument de ligne de commande)
  -f, --fichier CHEMIN     dépose le contenu du fichier indiqué
  -y, --sans-confirmation  n'interrompt pas le dépôt si un secret est détecté
      --secrets MODE       bloquer | demander (défaut) | signaler
      --pour DEST[,DEST]   restreint la lecture aux identités désignées
                           (individu « alice.durand » ou groupe « @equipe »)
      --marquage TEXTE     mention libre ajoutée au marquage de l'instance
` + aideCommunes + aideAuthClient

// cmdPush dépose un contenu en mode aveugle : interrogation de la politique
// de l'instance, affichage avant envoi (ES-4), contrôles locaux — jamais un
// contournement silencieux —, chiffrement local selon le schéma imposé,
// dépôt, puis restitution de l'identifiant sur la sortie standard.
func cmdPush(ctx *Contexte, args []string) error {
	fs := nouveauFS("push")
	var com optionsCommunes
	com.enregistrer(fs)
	var auth optionsAuthClient
	auth.enregistrer(fs)
	var duree, fichier, secrets, pour, marquage string
	var lectureUnique, motDePasse, sansConfirmation bool
	fs.StringVar(&duree, "duree", "", "")
	fs.StringVar(&duree, "t", "", "")
	fs.BoolVar(&lectureUnique, "lecture-unique", false, "")
	fs.BoolVar(&lectureUnique, "b", false, "")
	fs.BoolVar(&motDePasse, "mot-de-passe", false, "")
	fs.BoolVar(&motDePasse, "p", false, "")
	fs.StringVar(&fichier, "fichier", "", "")
	fs.StringVar(&fichier, "f", "", "")
	fs.BoolVar(&sansConfirmation, "sans-confirmation", false, "")
	fs.BoolVar(&sansConfirmation, "y", false, "")
	fs.StringVar(&secrets, "secrets", "demander", "")
	fs.StringVar(&pour, "pour", "", "")
	fs.StringVar(&marquage, "marquage", "", "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aidePush)
		return nil
	}
	if err := verifierPositionnels(fs, 1, "ardoise [push] [OPTIONS] [FICHIER]"); err != nil {
		return err
	}
	if fs.NArg() == 1 {
		if fichier != "" {
			return erreurUsage("FICHIER et « --fichier » sont exclusifs")
		}
		fichier = fs.Arg(0)
	}
	if duree != "" {
		if _, err := config.ParseDuree(duree); err != nil {
			return erreurUsage("« --duree » : %v", err)
		}
	}
	switch secrets {
	case "bloquer", "demander", "signaler":
	default:
		return erreurUsage("« --secrets » : valeur « %s » inconnue (attendu : « bloquer », « demander » ou « signaler »)", secrets)
	}
	if pour != "" {
		for _, destinataire := range strings.Split(pour, ",") {
			destinataire = strings.TrimSpace(destinataire)
			if !reDestinataire.MatchString(destinataire) {
				return erreurUsage("« --pour » : destinataire « %s » invalide (attendu : une identité comme « alice.durand » ou un groupe comme « @equipe-reseau »)", destinataire)
			}
		}
	}

	s := nouvelleSortie(ctx, &com)
	cl, err := preparerClient(ctx, &com, &auth)
	if err != nil {
		return err
	}

	// La politique de l'instance est interrogée avant tout envoi et
	// opposée aux options demandées : une option incompatible provoque un
	// refus local, jamais un contournement silencieux (ES-4, ADR-002).
	politique, err := cl.Politique()
	if err != nil {
		return traduireErreurClient(err)
	}
	if politique.Mode != config.ModeAveugle {
		return Erreurf(CodeErreur, "le dépôt vers une instance en mode analysé n'est pas disponible dans cette version")
	}

	schema, ok := politique.Option(config.DimContenu)
	if !ok {
		return Erreurf(CodeErreur, "politique de l'instance illisible : schéma de protection absent")
	}
	var avecMotDePasse bool
	switch schema.ID {
	case "CHIF-2":
		if motDePasse {
			return Erreurf(CodeRefusPolitique,
				"« --mot-de-passe » refusé : la politique de l'instance retient la clé aléatoire seule (CHIF-2), sans mot de passe")
		}
	case "CHIF-1", "CHIF-3":
		// Le mot de passe est exigé par la politique : il est demandé même
		// sans « --mot-de-passe », le client ne pouvant pas l'affaiblir.
		avecMotDePasse = true
	default:
		return Erreurf(CodeErreur, "schéma de protection « %s » non pris en charge par cette version", schema.ID)
	}

	dureeEffective := politique.DureeDefaut
	if duree != "" {
		demandee, _ := config.ParseDuree(duree) // déjà validée ci-dessus
		if dureeMax, err := config.ParseDuree(politique.DureeMax); err == nil && demandee > dureeMax {
			return Erreurf(CodeRefusPolitique,
				"durée %s refusée : la politique de l'instance la borne à %s", config.FormatDuree(demandee), politique.DureeMax)
		}
		dureeEffective = config.FormatDuree(demandee)
	}

	lectureUniqueEffective := lectureUnique
	switch politique.LectureUnique {
	case config.LectureUniqueImposee:
		lectureUniqueEffective = true
	case config.LectureUniqueInterdit:
		if lectureUnique {
			return Erreurf(CodeRefusPolitique,
				"« --lecture-unique » refusée : la politique de l'instance l'interdit (un même contenu doit pouvoir servir plusieurs destinataires)")
		}
	}

	// Affichage avant envoi (docs/man.md, EXEMPLES) : l'utilisateur voit le
	// mode, le marquage et le cycle de vie avant que quoi que ce soit parte.
	s.infof("Instance : %s (mode aveugle, chiffrement local)", politique.Instance)
	if politique.MarquageActif {
		s.infof("Marquage : %s", politique.MarquageLibelle)
	}
	ligneDuree := "Durée    : " + dureeEffective
	if lectureUniqueEffective {
		ligneDuree += " — destruction à la première lecture"
	}
	s.infof("%s", ligneDuree)

	clair, err := lireContenu(ctx, fichier)
	if err != nil {
		return err
	}
	if politique.TailleMaxOctets > 0 && int64(len(clair)) > politique.TailleMaxOctets {
		return Erreurf(CodeTailleDepassee,
			"contenu de %s refusé : la taille maximale de l'instance est %s",
			config.FormatTaille(int64(len(clair))), politique.TailleMax)
	}

	// Point d'ancrage ARDOISE-0007 : la détection de secrets côté client
	// (ES-12, options --secrets/--sans-confirmation) s'insérera ici, avant
	// chiffrement.

	var saisie []byte
	if avecMotDePasse {
		if ctx.LireMotDePasse == nil {
			return Erreurf(CodeErreur, "aucun terminal disponible pour saisir le mot de passe exigé par la politique de l'instance")
		}
		saisie, err = ctx.LireMotDePasse("Mot de passe : ")
		if err != nil {
			return Erreurf(CodeErreur, "%v", err)
		}
	}
	defer crypto.Effacer(saisie)

	var chiffre, cle []byte
	switch schema.ID {
	case "CHIF-2":
		chiffre, cle, err = crypto.ChiffrerCle(clair)
	case "CHIF-3":
		chiffre, err = crypto.ChiffrerMotDePasse(clair, saisie)
	case "CHIF-1":
		chiffre, cle, err = crypto.ChiffrerCleMotDePasse(clair, saisie)
	}
	if err != nil {
		return Erreurf(CodeErreur, "chiffrement du contenu : %v", err)
	}
	defer crypto.Effacer(cle)

	reponse, err := cl.Deposer(&client.Depot{
		Chiffre:            chiffre,
		Duree:              duree,
		LectureUnique:      lectureUnique,
		MarquageComplement: marquage,
	})
	if err != nil {
		return traduireErreurClient(err)
	}

	// L'empreinte annoncée par l'instance doit être celle du chiffré
	// réellement envoyé : tout écart est signalé, jamais ignoré.
	if !crypto.EmpreintesEgales(reponse.Empreinte, crypto.Empreinte(chiffre)) {
		return Erreurf(CodeErreur, "l'empreinte annoncée par l'instance ne correspond pas au contenu déposé")
	}
	if !crypto.IDServeurValide(reponse.ID) {
		return Erreurf(CodeErreur, "identifiant inattendu retourné par l'instance")
	}

	identifiant := crypto.FormatIdentifiant(reponse.ID, cle)
	if com.json {
		return ecrireJSONSortie(ctx.Stdout, struct {
			Identifiant string `json:"identifiant"`
			ID          string `json:"id"`
			Empreinte   string `json:"empreinte"`
			Echeance    string `json:"echeance"`
		}{identifiant, reponse.ID, reponse.Empreinte, reponse.Echeance})
	}
	fmt.Fprintln(ctx.Stdout, identifiant)
	return nil
}

// lireContenu lit le contenu à déposer : le fichier indiqué, sinon
// l'entrée standard.
func lireContenu(ctx *Contexte, fichier string) ([]byte, error) {
	if fichier != "" {
		donnees, err := os.ReadFile(fichier)
		if err != nil {
			return nil, Erreurf(CodeErreur, "lecture du contenu : %v", err)
		}
		if len(donnees) == 0 {
			return nil, Erreurf(CodeUsage, "le fichier « %s » est vide : rien à déposer", fichier)
		}
		return donnees, nil
	}
	donnees, err := io.ReadAll(ctx.Stdin)
	if err != nil {
		return nil, Erreurf(CodeErreur, "lecture de l'entrée standard : %v", err)
	}
	if len(donnees) == 0 {
		return nil, Erreurf(CodeUsage, "entrée standard vide : rien à déposer")
	}
	return donnees, nil
}
