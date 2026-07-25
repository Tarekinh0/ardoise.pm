package cli

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

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
      --annuaire CHEMIN    annuaire de clés publiques des destinataires :
                           avec --pour, chiffre pour chaque destinataire
                           (aussi : ARDOISE_ANNUAIRE, configuration client)
      --marquage TEXTE     mention libre ajoutée au marquage de l'instance
` + aideCommunes + aideAuthClient

// optionsPush regroupe les options de la commande push (PR-102) — extrait du
// corps de cmdPush pour en réduire la longueur.
type optionsPush struct {
	duree, fichier, secrets, pour, annuaire, marquage string
	lectureUnique, motDePasse, sansConfirmation       bool
}

// enregistrer déclare les drapeaux de push sur le jeu fourni.
func (o *optionsPush) enregistrer(fs *flag.FlagSet) {
	fs.StringVar(&o.duree, "duree", "", "")
	fs.StringVar(&o.duree, "t", "", "")
	fs.BoolVar(&o.lectureUnique, "lecture-unique", false, "")
	fs.BoolVar(&o.lectureUnique, "b", false, "")
	fs.BoolVar(&o.motDePasse, "mot-de-passe", false, "")
	fs.BoolVar(&o.motDePasse, "p", false, "")
	fs.StringVar(&o.fichier, "fichier", "", "")
	fs.StringVar(&o.fichier, "f", "", "")
	fs.BoolVar(&o.sansConfirmation, "sans-confirmation", false, "")
	fs.BoolVar(&o.sansConfirmation, "y", false, "")
	fs.StringVar(&o.secrets, "secrets", "", "")
	fs.StringVar(&o.pour, "pour", "", "")
	fs.StringVar(&o.annuaire, "annuaire", "", "")
	fs.StringVar(&o.marquage, "marquage", "", "")
}

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
	var opts optionsPush
	opts.enregistrer(fs)

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
		if opts.fichier != "" {
			return erreurUsage("FICHIER et « --fichier » sont exclusifs")
		}
		opts.fichier = fs.Arg(0)
	}
	var dureeDemandee time.Duration
	if opts.duree != "" {
		var err error
		dureeDemandee, err = config.ParseDuree(opts.duree)
		if err != nil {
			return erreurUsage("« --duree » : %v", err)
		}
	}
	switch opts.secrets {
	case "", "bloquer", "demander", "signaler":
	default:
		return erreurUsage("« --secrets » : valeur « %s » inconnue (attendu : « bloquer », « demander » ou « signaler »)", opts.secrets)
	}
	var pourListe []string
	if opts.pour != "" {
		for _, destinataire := range strings.Split(opts.pour, ",") {
			destinataire = strings.TrimSpace(destinataire)
			if !reDestinataire.MatchString(destinataire) {
				return erreurUsage("« --pour » : destinataire « %s » invalide (attendu : une identité comme « alice.durand » ou un groupe comme « @equipe-reseau »)", destinataire)
			}
			pourListe = append(pourListe, destinataire)
		}
	}

	s := nouvelleSortie(ctx, &com)
	cl, cfgClient, err := preparerClient(ctx, &com, &auth)
	if err != nil {
		return err
	}

	// Négociation de la politique de l'instance : schéma, durée,
	// lecture unique, destinataires, affichage.
	neg, err := resoudrePolitiquePush(ctx, s, cl, cfgClient, opts, dureeDemandee, pourListe)
	if err != nil {
		return err
	}

	clair, err := lireContenu(ctx, opts.fichier, neg.politique.TailleMaxOctets)
	if err != nil {
		return err
	}
	defer crypto.Effacer(clair)
	// PR-001 : la borne dure PlafondClientTaille s'applique même quand
	// l'instance ne déclare pas de limite (TailleMaxOctets == 0). Le +1
	// dans lireContenu garantit la détection de dépassement : un contenu
	// qui atteint PlafondClientTaille+1 a nécessairement débordé.
	if int64(len(clair)) > PlafondClientTaille {
		return Erreurf(CodeTailleDepassee,
			"contenu de %s refusé : la taille maximale autorisée est %s",
			config.FormatTaille(int64(len(clair))), config.FormatTaille(PlafondClientTaille))
	}
	if neg.politique.TailleMaxOctets > 0 && int64(len(clair)) > neg.politique.TailleMaxOctets {
		return Erreurf(CodeTailleDepassee,
			"contenu de %s refusé : la taille maximale de l'instance est %s",
			config.FormatTaille(int64(len(clair))), neg.politique.TailleMax)
	}

	if err := controlerSecrets(ctx, s, clair, modeSecretsEffectif(neg.politique.SecretsClient, opts.secrets), opts.sansConfirmation); err != nil {
		return err
	}

	var saisie []byte
	if neg.avecMotDePasse {
		if ctx.LireMotDePasse == nil {
			return Erreurf(CodeErreur, "aucun terminal disponible pour saisir le mot de passe exigé par la politique de l'instance")
		}
		saisie, err = ctx.LireMotDePasse("Mot de passe : ")
		if err != nil {
			return Erreurf(CodeErreur, "%v", err)
		}
	}
	defer crypto.Effacer(saisie)

	chiffre, cle, err := preparerChiffrement(neg.modeAnalyse, neg.chiffrementMD, neg.schemaID, clair, saisie, neg.destinatairesMD)
	if err != nil {
		return err
	}
	defer crypto.Effacer(cle)

	return envoyerEtVerifier(cl, ctx, chiffre, cle, clair, neg.modeAnalyse, neg.chiffrementMD, neg.dureeEffective, neg.lectureUniqueEffective, pourListe, opts.marquage, &com)
}

// negociationPush rassemble les paramètres issus de la négociation avec la
// politique de l'instance (PR-102). Chaque champ a été validé — schéma,
// durée, lecture unique, mode — et les décisions sont définitives.
type negociationPush struct {
	politique              *config.Politique
	modeAnalyse            bool
	avecMotDePasse         bool
	dureeEffective         string
	lectureUniqueEffective bool
	chiffrementMD          bool
	schemaID               string
	destinatairesMD        []crypto.DestinataireMD
}

// resoudrePolitiquePush interroge l'instance, résout les options du dépôt
// contre la politique publiée et affiche le résumé sur la sortie standard
// (mode, marquage, durée). Extraite de cmdPush (PR-102).
func resoudrePolitiquePush(ctx *Contexte, s *sortie, cl *client.Client, cfgClient *config.Client, opts optionsPush, dureeDemandee time.Duration, pourListe []string) (*negociationPush, error) {
	politique, err := cl.Politique()
	if err != nil {
		return nil, traduireErreurClient(err)
	}
	modeAnalyse := politique.Mode == config.ModeAnalyse

	if len(pourListe) > 0 && !politique.DestinatairesAdmis {
		return nil, Erreurf(CodeRefusPolitique,
			"« --pour » refusé : l'instance retient l'identification déclarative, dont l'identité du lecteur — falsifiable — ne peut fonder aucune restriction de lecture")
	}

	var destinatairesMD []crypto.DestinataireMD
	if len(pourListe) > 0 {
		cheminAnnuaire := premierNonVide(opts.annuaire, cfgClient.Annuaire)
		if cheminAnnuaire != "" {
			if modeAnalyse {
				s.infof("Mode analysé : le chiffrement multi-destinataires ne s'applique pas (clé générée par le serveur, CHIF-4) — désignation appliquée par l'instance seule")
			} else {
				table, errAnnuaire := chargerAnnuaire(cheminAnnuaire)
				if errAnnuaire != nil {
					return nil, Erreurf(CodeErreur, "%v", errAnnuaire)
				}
				destinatairesMD = destinatairesChiffrement(s, pourListe, table)
			}
		}
	}
	chiffrementMD := len(destinatairesMD) > 0
	if chiffrementMD && opts.motDePasse {
		return nil, Erreurf(CodeRefusPolitique,
			"« --mot-de-passe » est sans objet avec le chiffrement multi-destinataires : chaque destinataire ouvre avec sa propre clé privée")
	}

	schema, ok := politique.Option(config.DimContenu)
	if !ok {
		return nil, Erreurf(CodeErreur, "politique de l'instance illisible : schéma de protection absent")
	}

	avecMotDePasse, err := resoudreSchema(modeAnalyse, schema.ID, opts.motDePasse, chiffrementMD)
	if err != nil {
		return nil, err
	}

	// La durée est formatée pour le transport ; le serveur la décode avec
	// ParseDuree. Ce round-trip FormatDuree → ParseDuree est fragile :
	// un écart de format entre les deux fonctions casserait silencieusement
	// l'interprétation. L'envoi en secondes entières serait plus robuste
	// (PR-104 — correction différée, nécessite une coordination client/serveur).
	dureeEffective := politique.DureeDefaut
	if opts.duree != "" {
		dureeMax, err := config.ParseDuree(politique.DureeMax)
		if err != nil {
			return nil, Erreurf(CodeErreur,
				"politique de l'instance inexploitable : durée maximale « %s » illisible", politique.DureeMax)
		}
		if dureeDemandee > dureeMax {
			return nil, Erreurf(CodeRefusPolitique,
				"durée %s refusée : la politique de l'instance la borne à %s", config.FormatDuree(dureeDemandee), politique.DureeMax)
		}
		dureeEffective = config.FormatDuree(dureeDemandee)
	}

	lectureUniqueEffective := opts.lectureUnique
	switch politique.LectureUnique {
	case config.LectureUniqueImposee:
		lectureUniqueEffective = true
	case config.LectureUniqueInterdit:
		if opts.lectureUnique {
			return nil, Erreurf(CodeRefusPolitique,
				"« --lecture-unique » refusée : la politique de l'instance l'interdit (un même contenu doit pouvoir servir plusieurs destinataires)")
		}
	}

	if modeAnalyse {
		s.infof("Instance : %s (mode analysé — le serveur accède au contenu en clair pendant l'analyse)", politique.Instance)
	} else {
		s.infof("Instance : %s (mode aveugle, chiffrement local)", politique.Instance)
	}
	if politique.MarquageActif {
		s.infof("Marquage : %s", politique.MarquageLibelle)
	}
	ligneDuree := "Durée    : " + dureeEffective
	if lectureUniqueEffective {
		ligneDuree += " — destruction à la première lecture"
	}
	s.infof("%s", ligneDuree)

	return &negociationPush{
		politique:              politique,
		modeAnalyse:            modeAnalyse,
		avecMotDePasse:         avecMotDePasse,
		dureeEffective:         dureeEffective,
		lectureUniqueEffective: lectureUniqueEffective,
		chiffrementMD:          chiffrementMD,
		schemaID:               schema.ID,
		destinatairesMD:        destinatairesMD,
	}, nil
}

// resoudreSchema détermine le schéma de protection effectif et indique si un
// mot de passe est requis. En mode analysé, seul CHIF-4 est accepté et aucun
// mot de passe n'est applicable. En mode aveugle, le schéma est imposé par la
// politique de l'instance (CHIF-1, CHIF-2, CHIF-3 ; CHIF-MD via chiffrement
// multi-destinataires).
func resoudreSchema(modeAnalyse bool, schemaID string, motDePasse bool, chiffrementMD bool) (bool, error) {
	if modeAnalyse {
		if schemaID != "CHIF-4" {
			return false, Erreurf(CodeErreur, "schéma de protection « %s » non pris en charge par cette version", schemaID)
		}
		if motDePasse {
			return false, Erreurf(CodeRefusPolitique,
				"« --mot-de-passe » refusé : en mode analysé la clé est générée par le serveur (CHIF-4), aucun mot de passe ne s'y applique")
		}
		return false, nil
	}
	switch schemaID {
	case "CHIF-2":
		if motDePasse {
			return false, Erreurf(CodeRefusPolitique,
				"« --mot-de-passe » refusé : la politique de l'instance retient la clé aléatoire seule (CHIF-2), sans mot de passe")
		}
		return false, nil
	case "CHIF-1", "CHIF-3":
		return !chiffrementMD, nil
	default:
		return false, Erreurf(CodeErreur, "schéma de protection « %s » non pris en charge par cette version", schemaID)
	}
}

// preparerChiffrement chiffre le contenu selon le schéma de protection.
// En mode analysé, le contenu est envoyé en clair (le chiffrement est
// l'affaire du serveur, CHIF-4). En mode aveugle, le chiffrement est
// effectué localement — CHIF-1, CHIF-2, CHIF-3 ou CHIF-MD.
func preparerChiffrement(modeAnalyse bool, chiffrementMD bool, schemaID string, clair []byte, saisie []byte, destinatairesMD []crypto.DestinataireMD) (chiffre []byte, cle []byte, err error) {
	if modeAnalyse {
		return nil, nil, nil
	}
	if chiffrementMD {
		chiffre, err = crypto.ChiffrerMultiDest(clair, destinatairesMD)
		return chiffre, nil, err
	}
	switch schemaID {
	case "CHIF-2":
		return crypto.ChiffrerCle(clair)
	case "CHIF-3":
		chiffre, err = crypto.ChiffrerMotDePasse(clair, saisie)
		return chiffre, nil, err
	case "CHIF-1":
		return crypto.ChiffrerCleMotDePasse(clair, saisie)
	default:
		return nil, nil, Erreurf(CodeErreur, "schéma de protection « %s » non pris en charge par cette version", schemaID)
	}
}

// envoyerEtVerifier dépose le contenu, vérifie la réponse de l'instance et
// formate l'identifiant sur la sortie standard. En mode aveugle, l'empreinte
// retournée est comparée à celle du chiffré. En mode analysé, la clé CHIF-4
// est extraite de la réponse et intégrée à l'identifiant.
func envoyerEtVerifier(cl *client.Client, ctx *Contexte, chiffre []byte, cle []byte, clair []byte, modeAnalyse bool, chiffrementMD bool, duree string, lectureUnique bool, pourListe []string, marquage string, com *optionsCommunes) error {
	envoi := clair
	if !modeAnalyse {
		envoi = chiffre
	}
	reponse, err := cl.Deposer(&client.Depot{
		Contenu:            envoi,
		Duree:              duree,
		LectureUnique:      lectureUnique,
		Pour:               pourListe,
		MarquageComplement: marquage,
	})
	if err != nil {
		return traduireErreurClient(err)
	}
	if !crypto.IDServeurValide(reponse.ID) {
		return Erreurf(CodeErreur, "identifiant inattendu retourné par l'instance")
	}

	if modeAnalyse {
		cleServeur, errCle := base64.RawURLEncoding.DecodeString(reponse.Cle)
		if errCle != nil || len(cleServeur) != crypto.TailleCle {
			crypto.Effacer(cleServeur)
			return Erreurf(CodeErreur, "clé inattendue retournée par l'instance")
		}
		cle = cleServeur
		defer crypto.Effacer(cle)
	} else {
		if !crypto.EmpreintesEgales(reponse.Empreinte, crypto.Empreinte(chiffre)) {
			return Erreurf(CodeErreur, "l'empreinte annoncée par l'instance ne correspond pas au contenu déposé")
		}
	}

	identifiant := crypto.FormatIdentifiant(reponse.ID, cle)
	if chiffrementMD {
		identifiant = crypto.FormatIdentifiantMultiDest(reponse.ID)
	}
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

// PlafondClientTaille est la borne mémoire dure côté client lorsqu'aucune
// borne configurée n'est fournie par l'instance (TailleMaxOctets == 0).
// 64 Mio : le service n'est pas un serveur de fichiers (ES-10) et aucun
// contenu légitime de pastebin ne dépasse ce seuil (SRQ-B001).
const PlafondClientTaille = 64 << 20 // 64 Mio

// lireContenu lit le contenu à déposer : le fichier indiqué, sinon l'entrée
// standard. La lecture est bornée par tailleMaxOctets (limite configurée de
// l'instance). Lorsque tailleMaxOctets est nul (pas de limite configurée),
// un plafond dur de 64 Mio est appliqué. Le +1 permet de détecter un
// dépassement sans tronquer silencieusement (DPO-B-001).
func lireContenu(ctx *Contexte, fichier string, tailleMaxOctets int64) ([]byte, error) {
	limite := tailleMaxOctets + 1
	if tailleMaxOctets <= 0 {
		limite = PlafondClientTaille + 1
	}
	if fichier != "" {
		f, err := os.Open(fichier)
		if err != nil {
			return nil, Erreurf(CodeErreur, "lecture du contenu : %v", err)
		}
		defer f.Close()
		donnees, err := io.ReadAll(io.LimitReader(f, limite))
		if err != nil {
			return nil, Erreurf(CodeErreur, "lecture du contenu : %v", err)
		}
		if len(donnees) == 0 {
			return nil, Erreurf(CodeUsage, "le fichier « %s » est vide : rien à déposer", fichier)
		}
		return donnees, nil
	}
	donnees, err := io.ReadAll(io.LimitReader(ctx.Stdin, limite))
	if err != nil {
		return nil, Erreurf(CodeErreur, "lecture de l'entrée standard : %v", err)
	}
	if len(donnees) == 0 {
		return nil, Erreurf(CodeUsage, "entrée standard vide : rien à déposer")
	}
	return donnees, nil
}
