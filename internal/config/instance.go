// Package config charge et valide les configurations d'instance et de
// client d'ardoise.pm.
//
// Le format est JSON strict — tout champ inconnu est une erreur — avec les
// mêmes clés et la même structure que l'exemple du manuel (docs/man.md,
// amendé par le propriétaire : JSON et non TOML). Chaque option correspond
// à un identifiant du document d'architecture (docs/dat.md §5) ; toute
// option omise prend sa valeur la plus prudente (règle du manuel).
//
// Valeurs par défaut retenues (« valeur la plus prudente ») :
//
//	Champ                     Défaut              Option   Justification
//	─────────────────────────────────────────────────────────────────────────────
//	instance.mode             "aveugle"           —        le serveur ne peut jamais lire les contenus
//	auth.mecanisme            "mtls-materiel"     AUTH-1   R+ : mécanisme le plus robuste ;
//	                                                       exige auth.ac_clients (refus sinon)
//	auth.ac_clients           ""                  AUTH-1/2 AC des certificats clients : requis avec
//	                                                       les mécanismes « mtls-materiel » et
//	                                                       « mtls », sans objet (refusé) sinon
//	auth.champ_identite       "CN"                —        champ d'identité usuel des certificats
//	                                                       internes ; « SAN:email », « SAN:dns » et
//	                                                       « SAN:uri » admis (AUTH-2)
//	auth.jetons               ""                  AUTH-3   table des jetons (JSON : identité →
//	                                                       SHA-256 hexadécimale du jeton, droits
//	                                                       0600) : requis avec le mécanisme
//	                                                       « jeton », sans objet (refusé) sinon —
//	                                                       aucun jeton ne peut être inventé
//	auth.groupes              ""                  —        table optionnelle des groupes de
//	                                                       destinataires (JSON : « @groupe » →
//	                                                       identités membres) pour « --pour » ;
//	                                                       refusée sous « declaratif » où la
//	                                                       désignation est elle-même refusée
//	contenu.chiffrement       "cle"                  CHIF-2   R en mode aveugle ; en mode analyse le défaut
//	                          (ou "serveur")         CHIF-4   est "serveur", seule valeur admissible du mode
//	contenu.taille_max        "256Kio"            —        borne de l'exemple du manuel ; le service
//	                                                       n'est pas un serveur de fichiers (ES-10)
//	retention.support         "memoire"           RET-2    aucune persistance sur support
//	retention.lecture_unique  "imposee"           RET-1    R+ : destruction à la première lecture
//	retention.duree_max       "1h"                TTL-1    R+ : fenêtre d'exposition minimale
//	retention.duree_defaut    min(1h, duree_max)  —        jamais supérieure à la borne de l'instance
//	retention.repertoire      "/var/lib/ardoise"  RET-3    magasin sur support (docs/man.md, FICHIERS) ;
//	                                                       sans objet (refusé) avec support "memoire"
//	retention.cle_magasin     ""                  RET-3    chemin du fichier de clé chiffrant le magasin
//	                                                       sur disque (32 octets bruts ou 64 hexadécimaux,
//	                                                       droits 0600 au plus) ; requis avec le support
//	                                                       "disque-chiffre", refusé avec "memoire" —
//	                                                       aucune clé ne peut être inventée
//	cache.politique           "interdit"          CACHE-1  aucune rémanence côté client
//	analyse.secrets_client    "bloquer"           —        refus de dépôt en cas de secret détecté
//	analyse.icap_url          ""                  —        requis en mode analyse : son absence
//	                                                       empêche le démarrage (man.md)
//	analyse.icap_delai        "10s"               —        valeur de l'exemple du manuel
//	analyse.icap_regles       ""                  —        jeu de règles complémentaire, optionnel
//	journal.destination       "aucun"             JOURN-4  une destination de collecte ne peut être
//	                                                       inventée ; l'écart aux minima II 901 est
//	                                                       signalé par « serve --verifier »
//	journal.chainage          vrai si collecteur  JOURN-1  chaînage activé dès qu'une destination
//	                                                       de collecte le permet
//	journal.fichier           ""                  JOURN-3  chemin du journal local (une entrée JSON
//	                                                       par ligne, ajout seul, droits 0600) :
//	                                                       requis avec la destination « fichier »,
//	                                                       sans objet (refusé) sinon
//	journal.ac                ""                  JOURN-1/2 AC du collecteur syslog+tls (PEM) ;
//	                                                       à défaut, magasin système du poste —
//	                                                       sans objet (refusé) sans collecteur
//	transport.version_min     "1.3"               TLS-2    état de l'art (guide TLS de l'ANSSI)
//	transport.epinglage       true                —        épinglage de l'AC interne actif
//	marquage.actif            true                MARQ-1   marquage automatique ; marquage.libelle
//	                                                       reste requis, aucun libellé ne pouvant
//	                                                       être inventé (refus sinon)
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"ardoise.pm/internal/jsonutil"
)

// Modes de déploiement (docs/dat.md §4.5).
const (
	ModeAveugle = "aveugle"
	ModeAnalyse = "analyse"
)

// Valeurs de retention.lecture_unique (RET-1 et déclinaisons).
const (
	LectureUniqueImposee  = "imposee"
	LectureUniqueAuChoix  = "au-choix"
	LectureUniqueInterdit = "interdite"
)

// Probleme décrit une incohérence ou une valeur invalide détectée dans une
// configuration d'instance. Un démarrage avec au moins un Probleme est refusé.
type Probleme struct {
	Champ   string
	Message string
}

func (p Probleme) String() string {
	return p.Champ + " : " + p.Message
}

// Instance est la configuration effective d'une instance, défauts appliqués.
type Instance struct {
	Nom    string
	Mode   string
	Ecoute string

	Auth      Auth
	Contenu   Contenu
	Retention Retention
	Cache     Cache
	Analyse   Analyse
	Journal   Journal
	Transport Transport
	Marquage  Marquage
}

// Mécanismes d'identification (docs/dat.md §5.2, AUTH-1..4).
const (
	MecanismeMTLSMateriel = "mtls-materiel" // AUTH-1
	MecanismeMTLS         = "mtls"          // AUTH-2
	MecanismeJeton        = "jeton"         // AUTH-3
	MecanismeDeclaratif   = "declaratif"    // AUTH-4
)

// Auth : mécanisme d'identification imposé par l'instance (AUTH-1..4).
type Auth struct {
	Mecanisme     string
	ACClients     string
	ChampIdentite string
	Jetons        string // chemin de la table des jetons (AUTH-3)

	// Groupes est le chemin (optionnel) de la table des groupes de
	// destinataires : un fichier JSON associant chaque groupe (« @equipe »)
	// à ses membres, par exemple {"@equipe-reseau": ["alice.durand"]}.
	// Elle sert la désignation de destinataires (« --pour ») : au moment de
	// la lecture, un groupe absent de la table ne correspond à aucune
	// identité. Sans objet — et refusée — sous identification déclarative,
	// où « --pour » est structurellement refusé.
	Groupes string
}

// ExigeCertificatClient indique si l'instance exige un certificat client au
// niveau TLS (AUTH-1 et AUTH-2) : la poignée de main elle-même refuse alors
// tout client sans certificat vérifiable auprès de auth.ac_clients.
func (a Auth) ExigeCertificatClient() bool {
	return a.Mecanisme == MecanismeMTLS || a.Mecanisme == MecanismeMTLSMateriel
}

// DestinatairesAdmissibles indique si l'instance peut offrir la désignation
// de destinataires (« --pour », champ « pour » du dépôt). Sous identification
// déclarative (AUTH-4), elle est structurellement refusée : l'identité
// annoncée par le client est falsifiable, et la restriction de lecture à des
// identités désignées serait un faux-semblant (docs/man.md, « --pour »).
// La prise en charge de « pour » arrive dans une phase ultérieure
// (ARDOISE-0005) ; la règle est posée ici pour qu'elle ne puisse pas être
// oubliée à ce moment-là.
func (i *Instance) DestinatairesAdmissibles() bool {
	return i.Auth.Mecanisme != MecanismeDeclaratif
}

// Contenu : protection des contenus (CHIF-2, CHIF-4, CHIF-5) et taille maximale (ES-10).
type Contenu struct {
	Chiffrement    string
	TailleMaxTexte string
	TailleMax      int64 // renseignée par la validation
	MaxArdoises    int   // plafond du nombre d'ardoises (défaut 10000, S1)
}

// Retention : conservation et durée de vie (RET-1..3, TTL-1..3).
type Retention struct {
	Support          string
	LectureUnique    string
	DureeMaxTexte    string
	DureeDefautTexte string
	Repertoire       string        // magasin sur support (RET-3)
	CleMagasin       string        // chemin du fichier de clé du magasin (RET-3)
	DureeMax         time.Duration // renseignée par la validation
	DureeDefaut      time.Duration // renseignée par la validation

	repertoireExplicite bool
}

// Cache : rémanence côté client (CACHE-1..3).
type Cache struct {
	Politique string
}

// Analyse : analyse de contenu (ANA-1..4).
type Analyse struct {
	SecretsClient  string
	ICAPURL        string
	ICAPDelaiTexte string
	ICAPRegles     string
	ICAPDelai      time.Duration // renseignée par la validation
}

// Journal : journalisation et imputabilité (JOURN-1..4).
type Journal struct {
	Destination string
	Chainage    bool
	Fichier     string // journal local (JOURN-3) : requis avec destination "fichier"
	AC          string // AC du collecteur syslog+tls (PEM) ; défaut : magasin système

	chainageExplicite bool
}

// Transport : matériel et version TLS (TLS-2, TLS-3).
type Transport struct {
	Certificat string
	Cle        string
	VersionMin string
	Epinglage  bool
}

// Marquage : marquage de sensibilité (MARQ-1, MARQ-2).
type Marquage struct {
	Actif   bool
	Libelle string
}

// Structures de décodage strict : des pointeurs partout, afin de distinguer
// une valeur omise (défaut prudent) d'une valeur explicite.

type fichierInstance struct {
	Instance  *sectionInstance  `json:"instance"`
	Auth      *sectionAuth      `json:"auth"`
	Contenu   *sectionContenu   `json:"contenu"`
	Retention *sectionRetention `json:"retention"`
	Cache     *sectionCache     `json:"cache"`
	Analyse   *sectionAnalyse   `json:"analyse"`
	Journal   *sectionJournal   `json:"journal"`
	Transport *sectionTransport `json:"transport"`
	Marquage  *sectionMarquage  `json:"marquage"`
}

type sectionInstance struct {
	Nom    *string `json:"nom"`
	Mode   *string `json:"mode"`
	Ecoute *string `json:"ecoute"`
}

type sectionAuth struct {
	Mecanisme     *string `json:"mecanisme"`
	ACClients     *string `json:"ac_clients"`
	ChampIdentite *string `json:"champ_identite"`
	Jetons        *string `json:"jetons"`
	Groupes       *string `json:"groupes"`
}

type sectionContenu struct {
	Chiffrement *string `json:"chiffrement"`
	TailleMax   *string `json:"taille_max"`
	MaxArdoises *int    `json:"max_ardoises"`
}

type sectionRetention struct {
	Support       *string `json:"support"`
	LectureUnique *string `json:"lecture_unique"`
	DureeMax      *string `json:"duree_max"`
	DureeDefaut   *string `json:"duree_defaut"`
	Repertoire    *string `json:"repertoire"`
	CleMagasin    *string `json:"cle_magasin"`
}

type sectionCache struct {
	Politique *string `json:"politique"`
}

type sectionAnalyse struct {
	SecretsClient *string `json:"secrets_client"`
	ICAPURL       *string `json:"icap_url"`
	ICAPDelai     *string `json:"icap_delai"`
	ICAPRegles    *string `json:"icap_regles"`
}

type sectionJournal struct {
	Destination *string `json:"destination"`
	Chainage    *bool   `json:"chainage"`
	Fichier     *string `json:"fichier"`
	AC          *string `json:"ac"`
}

type sectionTransport struct {
	Certificat *string `json:"certificat"`
	Cle        *string `json:"cle"`
	VersionMin *string `json:"version_min"`
	Epinglage  *bool   `json:"epinglage"`
}

type sectionMarquage struct {
	Actif   *bool   `json:"actif"`
	Libelle *string `json:"libelle"`
}

// Charger lit et analyse la configuration d'instance au chemin donné.
// L'erreur retournée est fatale (lecture ou JSON illisible) ; les problèmes
// de validation et de cohérence sont retournés séparément afin que
// « serve --verifier » puisse tous les signaler.
func Charger(chemin string) (*Instance, []Probleme, error) {
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, nil, fmt.Errorf("lecture de la configuration : %w", err)
	}
	return Analyser(donnees)
}

// Analyser décode strictement une configuration d'instance JSON, applique
// les défauts prudents puis valide l'ensemble.
func Analyser(donnees []byte) (*Instance, []Probleme, error) {
	var f fichierInstance
	if err := decoderStrict(donnees, &f); err != nil {
		return nil, nil, fmt.Errorf("configuration JSON invalide : %w", err)
	}
	inst := resoudre(&f)
	return inst, inst.valider(), nil
}

// DecoderStrict expose le décodage strict du paquet aux autres tables JSON
// du produit (annuaire de clés publiques, notamment) : mêmes règles que
// les configurations — tout champ inconnu ou contenu excédentaire est une
// erreur.
//
// PR-101 : délégué à internal/jsonutil — le paquet config ne doit pas être
// le dépositaire d'un utilitaire JSON générique. Cette fonction demeure
// exportée pour la rétrocompatibilité des appelants internes au paquet config
// (tests, notamment).
func DecoderStrict(donnees []byte, cible any) error {
	return jsonutil.DecoderStrict(donnees, cible)
}

// decoderStrict décode du JSON en refusant tout champ inconnu et tout
// contenu excédentaire après l'objet racine. Délègue à jsonutil.
func decoderStrict(donnees []byte, cible any) error {
	return jsonutil.DecoderStrict(donnees, cible)
}

func defChaine(p *string, defaut string) string {
	if p == nil {
		return defaut
	}
	return *p
}

func defInt(p *int, defaut int) int {
	if p == nil {
		return defaut
	}
	return *p
}

// resoudre applique les défauts prudents documentés en tête de fichier.
func resoudre(f *fichierInstance) *Instance {
	si := f.Instance
	if si == nil {
		si = &sectionInstance{}
	}
	sa := f.Auth
	if sa == nil {
		sa = &sectionAuth{}
	}
	sc := f.Contenu
	if sc == nil {
		sc = &sectionContenu{}
	}
	sr := f.Retention
	if sr == nil {
		sr = &sectionRetention{}
	}
	sk := f.Cache
	if sk == nil {
		sk = &sectionCache{}
	}
	sn := f.Analyse
	if sn == nil {
		sn = &sectionAnalyse{}
	}
	sj := f.Journal
	if sj == nil {
		sj = &sectionJournal{}
	}
	st := f.Transport
	if st == nil {
		st = &sectionTransport{}
	}
	sm := f.Marquage
	if sm == nil {
		sm = &sectionMarquage{}
	}

	inst := &Instance{
		Nom:    defChaine(si.Nom, ""),
		Mode:   defChaine(si.Mode, ModeAveugle),
		Ecoute: defChaine(si.Ecoute, ""),
	}

	inst.Auth = Auth{
		Mecanisme:     defChaine(sa.Mecanisme, MecanismeMTLSMateriel),
		ACClients:     defChaine(sa.ACClients, ""),
		ChampIdentite: defChaine(sa.ChampIdentite, "CN"),
		Jetons:        defChaine(sa.Jetons, ""),
		Groupes:       defChaine(sa.Groupes, ""),
	}

	defautChiffrement := "cle"
	if inst.Mode == ModeAnalyse {
		defautChiffrement = "serveur"
	}
	inst.Contenu = Contenu{
		Chiffrement:    defChaine(sc.Chiffrement, defautChiffrement),
		TailleMaxTexte: defChaine(sc.TailleMax, "256Kio"),
		MaxArdoises:    defInt(sc.MaxArdoises, 10000),
	}

	inst.Retention = Retention{
		Support:             defChaine(sr.Support, "memoire"),
		LectureUnique:       defChaine(sr.LectureUnique, LectureUniqueImposee),
		DureeMaxTexte:       defChaine(sr.DureeMax, "1h"),
		DureeDefautTexte:    defChaine(sr.DureeDefaut, ""),
		Repertoire:          defChaine(sr.Repertoire, "/var/lib/ardoise"),
		CleMagasin:          defChaine(sr.CleMagasin, ""),
		repertoireExplicite: sr.Repertoire != nil,
	}

	inst.Cache = Cache{Politique: defChaine(sk.Politique, "interdit")}

	inst.Analyse = Analyse{
		SecretsClient:  defChaine(sn.SecretsClient, "bloquer"),
		ICAPURL:        defChaine(sn.ICAPURL, ""),
		ICAPDelaiTexte: defChaine(sn.ICAPDelai, "10s"),
		ICAPRegles:     defChaine(sn.ICAPRegles, ""),
	}

	destination := defChaine(sj.Destination, "aucun")
	if destination == "" {
		destination = "aucun"
	}
	inst.Journal = Journal{
		Destination: destination,
		Fichier:     defChaine(sj.Fichier, ""),
		AC:          defChaine(sj.AC, ""),
	}
	if sj.Chainage != nil {
		inst.Journal.Chainage = *sj.Chainage
		inst.Journal.chainageExplicite = true
	} else {
		inst.Journal.Chainage = estCollecteur(destination)
	}

	inst.Transport = Transport{
		Certificat: defChaine(st.Certificat, ""),
		Cle:        defChaine(st.Cle, ""),
		VersionMin: defChaine(st.VersionMin, "1.3"),
		Epinglage:  true,
	}
	if st.Epinglage != nil {
		inst.Transport.Epinglage = *st.Epinglage
	}

	inst.Marquage = Marquage{Actif: true, Libelle: defChaine(sm.Libelle, "")}
	if sm.Actif != nil {
		inst.Marquage.Actif = *sm.Actif
	}

	return inst
}

// estCollecteur indique si la destination de journalisation est une zone de
// collecte centrale (JOURN-1/JOURN-2), par opposition à « fichier » (JOURN-3)
// et « aucun » (JOURN-4).
func estCollecteur(destination string) bool {
	return strings.HasPrefix(destination, "syslog+tls://")
}

// PlafondTTL est la durée de vie maximale autorisée par l'option la plus
// permissive (TTL-3, 168 h). Au-delà, la configuration est invalide :
// la conservation illimitée n'existe pas dans le produit (ADR-003).
const PlafondTTL = 168 * time.Hour

// valider contrôle les énumérations, analyse les valeurs textuelles
// (durées, taille) et vérifie la cohérence entre champs. Tous les problèmes
// sont retournés, pas seulement le premier.
//
// Contrôles hors de portée de cette validation (points d'ancrage) :
//   - le refus de « --pour » sous identification déclarative (AUTH-4) est
//     porté par DestinatairesAdmissibles, appliqué par le serveur ;
//   - en mode analyse, vérification organisationnelle que la source
//     d'identités est distincte du SI d'administration (R56, §6.3) —
//     invérifiable depuis le seul fichier de configuration.
func (i *Instance) valider() []Probleme {
	var ps []Probleme
	ajouter := func(champ, format string, args ...any) {
		ps = append(ps, Probleme{Champ: champ, Message: fmt.Sprintf(format, args...)})
	}

	// [instance]
	if i.Nom == "" {
		ajouter("instance.nom", "requis : chaque instance doit porter un nom")
	}
	modeValide := i.Mode == ModeAveugle || i.Mode == ModeAnalyse
	if !modeValide {
		ajouter("instance.mode", "valeur « %s » inconnue (attendu : « aveugle » ou « analyse »)", i.Mode)
	}
	if i.Ecoute != "" {
		if _, _, err := net.SplitHostPort(i.Ecoute); err != nil {
			ajouter("instance.ecoute", "adresse « %s » invalide (attendu : hôte:port)", i.Ecoute)
		}
	}

	// [auth]
	// En mode analyse, quel que soit le mécanisme, la source des identités
	// (IGC des certificats clients, service d'identité des jetons) doit être
	// distincte du SI d'administration (R56, docs/dat.md §6.3 et ADR-009).
	// Cette exigence organisationnelle est invérifiable depuis le seul
	// fichier de configuration : point d'ancrage pour une vérification
	// d'exploitation, hors de portée de cette validation.
	if _, ok := optionsAuth[i.Auth.Mecanisme]; !ok {
		ajouter("auth.mecanisme", "valeur « %s » inconnue (attendu : « mtls-materiel », « mtls », « jeton » ou « declaratif »)", i.Auth.Mecanisme)
	} else {
		if i.Auth.ExigeCertificatClient() && i.Auth.ACClients == "" {
			ajouter("auth.ac_clients", "requis pour le mécanisme « %s » : l'instance doit connaître l'AC des certificats clients", i.Auth.Mecanisme)
		}
		if !i.Auth.ExigeCertificatClient() && i.Auth.ACClients != "" {
			ajouter("auth.ac_clients", "sans objet avec le mécanisme « %s » : aucun certificat client n'est demandé", i.Auth.Mecanisme)
		}
		if i.Auth.Mecanisme == MecanismeJeton && i.Auth.Jetons == "" {
			ajouter("auth.jetons", "requis pour le mécanisme « jeton » : table des jetons (JSON : identité → SHA-256 hexadécimale du jeton, droits 0600)")
		}
		if i.Auth.Mecanisme != MecanismeJeton && i.Auth.Jetons != "" {
			ajouter("auth.jetons", "sans objet avec le mécanisme « %s » : aucun jeton n'est accepté", i.Auth.Mecanisme)
		}
		if i.Auth.Mecanisme == MecanismeDeclaratif && i.Mode == ModeAnalyse {
			ajouter("auth.mecanisme", "l'identification déclarative (AUTH-4) est réservée au mode « aveugle » (docs/dat.md §5.2)")
		}
		if i.Auth.Mecanisme == MecanismeDeclaratif && i.Auth.Groupes != "" {
			ajouter("auth.groupes", "sans objet avec le mécanisme « declaratif » : la désignation de destinataires y est structurellement refusée (docs/man.md, « --pour »)")
		}
	}
	switch i.Auth.ChampIdentite {
	case "CN", "SAN:email", "SAN:dns", "SAN:uri":
	default:
		ajouter("auth.champ_identite", "valeur « %s » inconnue (attendu : « CN », « SAN:email », « SAN:dns » ou « SAN:uri »)", i.Auth.ChampIdentite)
	}

	// [contenu]
	if _, ok := optionsChiffrement[i.Contenu.Chiffrement]; !ok {
		ajouter("contenu.chiffrement", "valeur « %s » inconnue (attendu : « cle » ou « serveur ») — les schémas CHIF-5 (--mots) et CHIF-MD (--annuaire) sont des choix exclusivement client, jamais des valeurs de configuration serveur", i.Contenu.Chiffrement)
	} else if modeValide {
		if i.Mode == ModeAnalyse && i.Contenu.Chiffrement != "serveur" {
			ajouter("contenu.chiffrement", "le mode « analyse » impose « serveur » (CHIF-4) : le serveur chiffre après le verdict d'analyse")
		}
		if i.Mode == ModeAveugle && i.Contenu.Chiffrement == "serveur" {
			ajouter("contenu.chiffrement", "« serveur » (CHIF-4) est réservé au mode « analyse » : en mode aveugle le serveur ne voit jamais le clair")
		}
	}
	if taille, err := ParseTaille(i.Contenu.TailleMaxTexte); err != nil {
		ajouter("contenu.taille_max", "%v", err)
	} else {
		i.Contenu.TailleMax = taille
	}

	// [retention]
	switch i.Retention.Support {
	case "memoire", "disque-chiffre":
	default:
		ajouter("retention.support", "valeur « %s » inconnue (attendu : « memoire » ou « disque-chiffre »)", i.Retention.Support)
	}
	switch i.Retention.LectureUnique {
	case LectureUniqueImposee, LectureUniqueAuChoix, LectureUniqueInterdit:
	default:
		ajouter("retention.lecture_unique", "valeur « %s » inconnue (attendu : « imposee », « au-choix » ou « interdite »)", i.Retention.LectureUnique)
	}
	switch i.Retention.Support {
	case "disque-chiffre":
		if i.Retention.CleMagasin == "" {
			ajouter("retention.cle_magasin", "requis avec le support « disque-chiffre » : le magasin sur disque est toujours chiffré et aucune clé ne peut être inventée (RET-3)")
		}
		if i.Retention.Repertoire == "" {
			ajouter("retention.repertoire", "requis avec le support « disque-chiffre » : emplacement du magasin (docs/man.md : /var/lib/ardoise/)")
		}
	case "memoire":
		if i.Retention.CleMagasin != "" {
			ajouter("retention.cle_magasin", "sans objet avec le support « memoire » : aucun magasin sur disque n'existe")
		}
		if i.Retention.repertoireExplicite {
			ajouter("retention.repertoire", "sans objet avec le support « memoire » : aucun magasin sur disque n'existe")
		}
	}
	if dureeMax, err := ParseDuree(i.Retention.DureeMaxTexte); err != nil {
		ajouter("retention.duree_max", "%v", err)
	} else {
		i.Retention.DureeMax = dureeMax
		if dureeMax > PlafondTTL {
			ajouter("retention.duree_max", "%s dépasse le plafond de %s (TTL-3) : aucune option de conservation au-delà n'existe (ADR-003)",
				FormatDuree(dureeMax), FormatDuree(PlafondTTL))
		}
	}
	if i.Retention.DureeDefautTexte == "" {
		defaut := time.Hour
		if i.Retention.DureeMax > 0 {
			defaut = min(time.Hour, i.Retention.DureeMax)
		}
		i.Retention.DureeDefaut = defaut
		i.Retention.DureeDefautTexte = FormatDuree(defaut)
	} else if dureeDefaut, err := ParseDuree(i.Retention.DureeDefautTexte); err != nil {
		ajouter("retention.duree_defaut", "%v", err)
	} else {
		i.Retention.DureeDefaut = dureeDefaut
		if i.Retention.DureeMax > 0 && dureeDefaut > i.Retention.DureeMax {
			ajouter("retention.duree_defaut", "%s dépasse duree_max (%s)",
				FormatDuree(dureeDefaut), FormatDuree(i.Retention.DureeMax))
		}
	}

	// [cache]
	if _, ok := optionsCache[i.Cache.Politique]; !ok {
		ajouter("cache.politique", "valeur « %s » inconnue (attendu : « interdit », « borne » ou « libre »)", i.Cache.Politique)
	}

	// [analyse]
	switch i.Analyse.SecretsClient {
	case "bloquer", "demander", "signaler", "desactive":
	default:
		ajouter("analyse.secrets_client", "valeur « %s » inconnue (attendu : « bloquer », « demander », « signaler » ou « desactive »)", i.Analyse.SecretsClient)
	}
	if delai, err := ParseDuree(i.Analyse.ICAPDelaiTexte); err != nil {
		ajouter("analyse.icap_delai", "%v", err)
	} else {
		i.Analyse.ICAPDelai = delai
	}
	if modeValide {
		if i.Mode == ModeAnalyse && i.Analyse.ICAPURL == "" {
			ajouter("analyse.icap_url", "requis en mode « analyse » : sans chaîne d'analyse, l'instance refuse de démarrer (R58, fail-closed)")
		}
		if i.Mode == ModeAveugle && i.Analyse.ICAPURL != "" {
			ajouter("analyse.icap_url", "sans objet en mode « aveugle » : le serveur ne peut pas analyser ce qu'il ne peut pas lire")
		}
	}
	if i.Analyse.ICAPURL != "" {
		u, err := url.Parse(i.Analyse.ICAPURL)
		if err != nil || u.Scheme != "icap" || u.Host == "" {
			ajouter("analyse.icap_url", "URL « %s » invalide (attendu : « icap://hôte:port/service », RFC 3507)", i.Analyse.ICAPURL)
		}
	}
	// SRQ-B003 / DPO-B-003 : icap_regles ne doit pas contenir de
	// caractères de retour à la ligne (\r, \n), vecteurs d'injection
	// d'en-tête ICAP. Toute occurrence est signalée — pas de
	// transformation silencieuse.
	if i.Analyse.ICAPRegles != "" {
		for i, b := range []byte(i.Analyse.ICAPRegles) {
			if b == '\r' || b == '\n' {
				ajouter("analyse.icap_regles",
					"caractère de contrôle interdit (0x%02X) à la position %d — les retours à la ligne ne sont pas admis dans l'en-tête X-Ardoise-Regles (DPO-B-003)",
					b, i)
			}
		}
	}

	// [journal]
	if err := validerDestinationJournal(i.Journal.Destination); err != nil {
		ajouter("journal.destination", "%v", err)
	}
	if i.Journal.chainageExplicite && i.Journal.Chainage && !estCollecteur(i.Journal.Destination) {
		ajouter("journal.chainage", "le chaînage (JOURN-1) requiert une destination de collecte « syslog+tls://… »")
	}
	if i.Journal.Destination == "fichier" && i.Journal.Fichier == "" {
		ajouter("journal.fichier", "requis avec la destination « fichier » (JOURN-3) : aucun chemin de journal ne peut être inventé")
	}
	if i.Journal.Destination != "fichier" && i.Journal.Fichier != "" {
		ajouter("journal.fichier", "sans objet avec la destination « %s » : aucun journal local n'existe", i.Journal.Destination)
	}
	if i.Journal.AC != "" && !estCollecteur(i.Journal.Destination) {
		ajouter("journal.ac", "sans objet sans collecteur « syslog+tls://… » : aucune connexion TLS de journalisation n'existe")
	}

	// [transport]
	switch i.Transport.VersionMin {
	case "1.3", "1.2":
	default:
		ajouter("transport.version_min", "valeur « %s » inconnue (attendu : « 1.3 » ou « 1.2 »)", i.Transport.VersionMin)
	}
	if i.Transport.Certificat == "" {
		ajouter("transport.certificat", "requis : le serveur refuse de démarrer sans matériel TLS")
	}
	if i.Transport.Cle == "" {
		ajouter("transport.cle", "requis : le serveur refuse de démarrer sans matériel TLS")
	}

	// [marquage]
	if i.Marquage.Actif && i.Marquage.Libelle == "" {
		ajouter("marquage.libelle", "requis lorsque le marquage est actif (MARQ-1) : aucun libellé ne peut être inventé")
	}

	return ps
}

func validerDestinationJournal(destination string) error {
	switch destination {
	case "aucun", "fichier":
		return nil
	}
	if estCollecteur(destination) {
		u, err := url.Parse(destination)
		if err != nil || u.Host == "" || u.Port() == "" {
			return fmt.Errorf("URL « %s » invalide (attendu : « syslog+tls://hôte:port », port explicite)", destination)
		}
		return nil
	}
	return fmt.Errorf("valeur « %s » inconnue (attendu : « aucun », « fichier » ou une URL « syslog+tls://hôte:port »)", destination)
}
