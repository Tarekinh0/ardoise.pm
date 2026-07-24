ARDOISE(1) — Manuel de l'utilisateur et de l'administrateur — ardoise.pm v0.1

---

## NOM

**ardoise** — dépôt et récupération de textes éphémères sur une instance interne

## SYNOPSIS

```
ardoise [push] [OPTIONS] [FICHIER]
ardoise get [OPTIONS] IDENTIFIANT
ardoise get [OPTIONS] -
ardoise info [OPTIONS]
ardoise purge [OPTIONS]
ardoise serve --config FICHIER [OPTIONS]
ardoise version
```

## DESCRIPTION

**ardoise** dépose un bloc de texte sur une instance interne et retourne un identifiant permettant de le récupérer. Le contenu est détruit à l'expiration de sa durée de vie, ou dès sa première lecture lorsque cette option est retenue.

Le même exécutable porte le client et le serveur. En l'absence de sous-commande, avec une entrée standard redirigée, `push` est implicite.

Le comportement de sécurité est déterminé par l'**instance**, non par le client : chiffrement, mécanisme d'identification, durée de vie maximale, taille maximale, analyse de contenu, journalisation et rémanence locale sont déclarés dans la configuration serveur. Le client interroge cette configuration avant chaque dépôt, l'affiche, et ne dispose d'aucun moyen de l'affaiblir. Une option incompatible avec la politique de l'instance provoque un refus, jamais un contournement silencieux.

**ardoise** n'est ni un coffre-fort de secrets, ni un serveur de fichiers, ni une archive. Voir **FONCTIONS ABSENTES**.

## COMMANDES

**push** [FICHIER]
: Dépose un contenu et affiche l'identifiant sur la sortie standard. Le contenu est lu sur l'entrée standard, ou dans FICHIER s'il est fourni. Commande par défaut.

**get** IDENTIFIANT
: Récupère un contenu et l'écrit sur la sortie standard, sans ajout ni mise en forme, afin de rester composable avec un tube ou une redirection. Un tiret (`-`) à la place de l'identifiant le fait lire sur l'entrée standard (voir **SÉCURITÉ**).

**info**
: Affiche la configuration effective de l'instance : mode, mécanisme d'identification exigé, bornes de durée de vie et de taille, régime d'analyse, politique de rémanence, niveau de marquage. Ne dépose rien et ne consomme aucune ardoise.

**purge**
: Efface le cache local du poste. Sans argument, purge les entrées expirées ; avec `--tout`, purge l'intégralité du cache.

**serve**
: Démarre une instance. Requiert `--config`.

**version**
: Affiche la version, l'empreinte du binaire et l'identifiant de compilation reproductible.

## OPTIONS COMMUNES

**-e**, **--endpoint** *URL*
: Instance à contacter. Par défaut : variable `ARDOISE_ENDPOINT`, puis fichier de configuration client.

**-q**, **--silencieux**
: Supprime les messages informatifs sur la sortie d'erreur. Les refus restent affichés.

**--json**
: Sortie structurée sur la sortie standard, pour usage en script.

**--sans-couleur**
: Désactive la colorisation. Également désactivée si `ARDOISE_NO_COLOR` est définie ou si la sortie n'est pas un terminal.

**-h**, **--aide**
: Affiche l'aide de la commande.

## OPTIONS DE DÉPÔT (push)

**-t**, **--duree** *DURÉE*
: Durée de vie de l'ardoise : `30m`, `2h`, `24h`. Doit rester dans les bornes de l'instance ; toute valeur supérieure est refusée (code 3). Par défaut : durée par défaut de l'instance.

**-b**, **--lecture-unique**
: Détruit le contenu dès sa première récupération. Certaines instances imposent ce comportement ; d'autres l'interdisent lorsqu'un même contenu doit servir plusieurs destinataires.

**-p**, **--mot-de-passe**
: Demande un mot de passe au terminal et l'intègre à la protection du contenu. Selon la politique de l'instance, il complète la clé aléatoire (le destinataire doit alors disposer des deux) ou s'y substitue. Jamais passé en argument de ligne de commande.

**-f**, **--fichier** *CHEMIN*
: Dépose le contenu du fichier indiqué, équivalent à le fournir en argument positionnel.

**-y**, **--sans-confirmation**
: N'interrompt pas le dépôt lorsqu'un secret est détecté dans le contenu (voir `--secrets`). À réserver aux traitements automatisés dont le contenu est maîtrisé.

**--secrets** *MODE*
: Comportement de la détection locale de secrets : `bloquer` (refus du dépôt), `demander` (confirmation interactive, défaut), `signaler` (avertissement sans interruption). L'instance peut imposer `bloquer` et interdire les autres valeurs.

**--pour** *DESTINATAIRE*[,*DESTINATAIRE*…]
: Restreint la lecture aux identités désignées. Un destinataire est une identité individuelle (`alice.durand`) ou un groupe de l'annuaire de l'entité, préfixé d'une arobase (`@equipe-reseau`). L'instance vérifie l'identité authentifiée du lecteur avant de servir le contenu ; un identifiant obtenu par un tiers non désigné est inexploitable. Option indisponible sur les instances retenant l'identification déclarative, cette dernière étant falsifiable. Sans `--pour`, l'ardoise est lisible par toute identité authentifiée présentant l'identifiant.

**--marquage** *TEXTE*
: Ajoute une mention libre au marquage automatique de l'instance. Ne remplace jamais ce dernier.

## OPTIONS DE RÉCUPÉRATION (get)

**-o**, **--sortie** *CHEMIN*
: Écrit le contenu dans un fichier au lieu de la sortie standard.

**-n**, **--sans-cache**
: N'utilise pas le cache local et n'y écrit pas, même lorsque l'instance l'autorise.

**--cache-seul**
: Ne contacte pas l'instance et sert exclusivement depuis le cache local. Échoue si l'entrée est absente ou expirée.

**--verifier-empreinte** *EMPREINTE*
: Compare l'empreinte du contenu chiffré reçu à la valeur fournie et refuse en cas d'écart.

## OPTIONS DE SERVEUR (serve)

**-c**, **--config** *FICHIER*
: Fichier de configuration de l'instance. Obligatoire.

**--verifier**
: Analyse la configuration, affiche la politique effective avec le niveau de chaque option selon la convention du référentiel (R, R‑, R‑‑, R+), signale toute incohérence, puis quitte sans démarrer le service. Destiné aux contrôles de conformité et aux dossiers d'homologation.

**--politique**
: Affiche la politique effective au format JSON et quitte. Utilisé pour verser une preuve de configuration à un dossier.

**--ecoute** *ADRESSE*
: Adresse et port d'écoute, si l'on souhaite les surcharger.

## AUTHENTIFICATION CLIENT

Le mécanisme est imposé par l'instance ; le client fournit le matériel correspondant.

**--certificat** *CHEMIN*, **--cle** *CHEMIN*
: Certificat client et clé privée, pour les instances exigeant une authentification par certificat. Peut provenir d'un support matériel via PKCS#11 (voir `--pkcs11`).

**--pkcs11** *URI*
: Utilise une clé portée par un support matériel (carte à puce, jeton). L'identité n'est pas extractible du support.

**--jeton** *CHEMIN*
: Fichier contenant le jeton délivré par le service d'identité de l'entité. Jamais passé en argument littéral.

**--ac** *CHEMIN*
: Autorité de certification à laquelle faire confiance pour valider l'instance. Par défaut : magasin déclaré dans la configuration client.

## FICHIER DE CONFIGURATION DE L'INSTANCE

Format TOML. Chaque option correspond à un identifiant du document d'architecture, rappelé en commentaire. Toute option omise prend sa valeur la plus prudente.

```toml
[instance]
nom     = "ardoise-adm-zone-reseau"
mode    = "aveugle"        # "aveugle" | "analyse"
ecoute  = "10.0.12.4:8443"

[auth]
# AUTH-1 "mtls-materiel" | AUTH-2 "mtls" | AUTH-3 "jeton" | AUTH-4 "declaratif"
mecanisme    = "mtls"
ac_clients   = "/etc/ardoise/ac-clients.pem"   # requis avec "mtls" et "mtls-materiel"
champ_identite = "CN"                          # "CN" | "SAN:email" | "SAN:dns" | "SAN:uri"
# AUTH-3 uniquement — requis avec mecanisme = "jeton", refusé sinon :
# jetons     = "/etc/ardoise/jetons.json"      # table JSON identité → empreinte SHA-256
#                                              # hexadécimale du jeton (jamais le jeton
#                                              # lui-même), droits 0600, lue au démarrage.
#                                              # Exemple : { "alice.durand": "9f86d081…" }
# En mode "analyse", la source d'identités doit être distincte du SI d'administration.

[contenu]
# CHIF-1 "cle+motdepasse" | CHIF-2 "cle" | CHIF-3 "motdepasse" | CHIF-4 "serveur"
chiffrement  = "cle"
taille_max   = "256Kio"

[retention]
support        = "memoire"   # RET-2 "memoire" | RET-3 "disque-chiffre"
lecture_unique = "au-choix"  # RET-1 "imposee" | "au-choix" | "interdite"
duree_max      = "24h"       # TTL-1 "1h" | TTL-2 "24h" | TTL-3 "168h"
duree_defaut   = "1h"
# RET-3 uniquement — refusés avec support = "memoire" :
# repertoire   = "/var/lib/ardoise"          # emplacement du magasin sur support
# cle_magasin  = "/etc/ardoise/magasin.cle"  # clé chiffrant le magasin (32 octets
#                                            # bruts ou 64 hexadécimaux, droits 0600)

[cache]
# CACHE-1 "interdit" | CACHE-2 "borne" | CACHE-3 "libre"
politique = "interdit"

[analyse]
secrets_client = "bloquer"   # ANA-3 : "bloquer" | "demander" | "signaler" | "desactive"
icap_url       = ""          # ANA-2 : requis en mode "analyse"
icap_delai     = "10s"
icap_regles    = ""          # ANA-1 : jeu de règles complémentaire de l'entité

[journal]
# JOURN-1 destination + chainage | JOURN-2 destination | JOURN-3 "fichier" | JOURN-4 "aucun"
destination = "syslog+tls://journal.adm.interne:6514"
chainage    = true

[transport]
certificat  = "/etc/ardoise/instance.pem"
cle         = "/etc/ardoise/instance.key"
version_min = "1.3"          # TLS-2 "1.3" | TLS-3 "1.2"
epinglage   = true

[marquage]
actif   = true               # MARQ-1 true | MARQ-2 false
libelle = "DIFFUSION RESTREINTE"
```

En mode `analyse`, une adresse ICAP est obligatoire : son absence empêche le démarrage. Le refus de dépôt en cas de verdict indisponible ou de délai dépassé n'est pas désactivable.

## FICHIER DE CONFIGURATION CLIENT

```toml
endpoint    = "https://ardoise.adm.interne:8443"
ac          = "/etc/pki/ac-interne.pem"
certificat  = "/etc/pki/poste.pem"
cle         = "/etc/pki/poste.key"
cache       = "~/.cache/ardoise"
```

Ce fichier est destiné à être poussé par la télédistribution de l'entité ; l'utilisateur n'a normalement rien à configurer.

## VARIABLES D'ENVIRONNEMENT

| Variable | Rôle |
|---|---|
| `ARDOISE_ENDPOINT` | Instance par défaut |
| `ARDOISE_AC` | Autorité de certification de confiance |
| `ARDOISE_CERTIFICAT`, `ARDOISE_CLE` | Matériel d'authentification par certificat |
| `ARDOISE_PKCS11` | URI du support matériel |
| `ARDOISE_JETON` | Chemin du fichier de jeton (jamais le jeton lui-même) |
| `ARDOISE_CACHE` | Emplacement du cache local |
| `ARDOISE_NO_COLOR` | Désactive la colorisation |

## FICHIERS

| Chemin | Rôle |
|---|---|
| `/etc/ardoise/ardoise.toml` | Configuration de l'instance |
| `/etc/ardoise/client.toml` | Configuration client à l'échelle du poste |
| `~/.config/ardoise/client.toml` | Configuration client de l'utilisateur |
| `~/.cache/ardoise/` | Cache local, si l'instance l'autorise |
| `/var/lib/ardoise/` | Magasin sur support, si `support = "disque-chiffre"` |

## CODES DE RETOUR

| Code | Signification |
|---|---|
| 0 | Succès |
| 1 | Erreur générale |
| 2 | Erreur d'usage |
| 3 | Option refusée par la politique de l'instance |
| 4 | Dépôt interrompu : secret détecté dans le contenu |
| 5 | Ardoise inexistante, expirée ou déjà consommée |
| 6 | Authentification refusée |
| 7 | Analyse de contenu défavorable ou indisponible |
| 8 | Taille maximale dépassée |
| 9 | Instance injoignable |

Le code 5 ne distingue pas l'inexistence de l'expiration : cette indifférenciation est volontaire et prive un tiers d'un moyen d'inférence.

## EXEMPLES

Déposer la fin d'un journal :

```
$ tail -n 200 /var/log/apache/error.log | ardoise
Instance : ardoise-adm-zone-reseau (mode aveugle, chiffrement local)
Marquage : DIFFUSION RESTREINTE
Durée    : 1h — destruction à la première lecture
a7f3k9x2#Zt8mQ4vР1nKcW7yE0sJdL5hB2gT6uX
```

Récupérer et vérifier un script sans l'exécuter :

```
$ ardoise get a7f3k9x2#Zt8m... | sh -n
```

Récupérer sans exposer l'identifiant aux autres utilisateurs de la machine :

```
$ ardoise get - < identifiant.txt
```

Déposer un fichier avec une durée courte et un mot de passe complémentaire :

```
$ ardoise -t 30m -p -f config-tmp.conf
Mot de passe :
```

Adresser un extrait à une personne, puis à une équipe :

```
$ ardoise --pour alice.durand < incident.log
$ journalctl -u nginx -n 100 | ardoise --pour @equipe-reseau,rssi -t 4h
```

Consulter la politique d'une instance avant de l'utiliser :

```
$ ardoise info -e https://ardoise-dr.adm.interne:8443
Mode                 : analysé (le serveur analyse les contenus déposés)
Identification       : certificat client — annuaire dédié
Durée de vie         : 24h maximum, 1h par défaut
Taille maximale      : 256 Kio
Analyse de contenu   : ICAP, bloquante
Rémanence locale     : interdite
Destinataires        : désignation exigée (individu ou groupe)
Marquage             : DIFFUSION RESTREINTE
```

Vérifier une configuration avant mise en service :

```
# ardoise serve --config /etc/ardoise/ardoise.toml --verifier
Politique effective :
  Identification    AUTH-2  (R)    certificat client, AC interne
  Contenu           CHIF-2  (R)    clé aléatoire par ardoise, chiffrement local
  Conservation      RET-2   (R)    mémoire vive
  Durée de vie      TTL-2   (R)    24h maximum
  Rémanence client  CACHE-1 (R)    interdite
  Destinataires     DEST-2  (R‑)   désignation exigée, groupes autorisés
  Analyse           ANA-3   (R‑)   détection de secrets côté client
  Journalisation    JOURN-1 (R+)   collecteur central, entrées chaînées
  Transport         TLS-2   (R)    TLS 1.3, épinglage actif
  Marquage          MARQ-1  (R)    « DIFFUSION RESTREINTE »
Configuration conforme aux minima II 901. Aucune incohérence détectée.
```

## SÉCURITÉ

**L'identifiant contient la clé.** Tout ce qui suit le caractère `#` est le matériel de déchiffrement ; il ne parvient jamais à l'instance. Un identifiant complet équivaut au contenu : il se transmet par un canal maîtrisé, ne se colle pas dans un outil de tickets, une messagerie externe ou un compte rendu.

**Sans destinataire désigné, l'ardoise est au porteur.** Toute identité authentifiée présentant l'identifiant peut lire. L'option `--pour` ajoute une seconde condition — être le destinataire désigné — de sorte qu'un identifiant intercepté ne suffise plus. Cette vérification est appliquée par l'instance : elle protège contre un tiers, non contre une instance compromise.

**Les arguments de ligne de commande sont visibles.** Sur une machine partagée, `ps` expose les arguments des processus des autres utilisateurs, et l'historique du shell conserve les commandes. Préférez `ardoise get -` avec l'identifiant sur l'entrée standard.

**Le mot de passe n'est jamais un argument.** Il est demandé au terminal. Aucune option ne permet de le fournir en ligne de commande.

**Le cache local contient du chiffré, jamais de clé.** Lorsqu'il est autorisé, il conserve le contenu tel qu'il a été reçu, indexé par l'empreinte de l'identifiant serveur : sans l'identifiant correspondant, il est inexploitable. Il n'en demeure pas moins une rémanence sur le poste, purgée au plus tard à l'échéance de l'ardoise.

**Le mode analysé n'est pas un chiffrement de bout en bout.** L'instance accède au contenu en clair le temps de l'analyse imposée. Le client l'indique avant chaque dépôt. En mode aveugle, l'instance ne peut à aucun moment lire les contenus.

**La détection de secrets est une aide, pas une garantie.** Elle reconnaît des formes connues d'authentifiants ; elle ne remplace pas la vigilance et ne dispense pas d'utiliser un coffre-fort de secrets pour ce qui en relève.

**L'identification déclarative n'authentifie rien.** Lorsqu'une instance retient ce mécanisme, l'identité consignée est celle que le client annonce. Les journaux la marquent comme déclarative et elle ne fonde aucune imputabilité opposable.

## FONCTIONS ABSENTES

Les fonctions suivantes n'existent pas et ne sont pas prévues. Leur absence est une propriété du produit, non une lacune.

- Aucune commande ne liste les ardoises présentes sur une instance : lister reviendrait à constituer l'inventaire que le produit refuse de tenir.
- Une ardoise ne se modifie pas : elle s'écrit une fois.
- Aucune recherche dans les contenus, que l'instance n'est de toute façon pas en mesure de lire en mode aveugle.
- Aucun compte utilisateur côté instance : les identités proviennent de l'entité.
- Aucune conservation illimitée.
- Aucun stockage de fichiers arbitraires : la taille maximale y fait obstacle. Ce besoin relève d'un serveur de fichiers.
- Aucune fonction de coffre-fort : le dépôt d'un authentifiant déclenche une alerte, et ce besoin relève d'un coffre-fort de mots de passe.
- Aucune liaison entre instances : ni fédération, ni réplication, ni recherche croisée.

## FONCTIONS RÉSERVÉES

Non implémentées à ce jour, à l'étude :

- Chiffrement à destination de plusieurs destinataires, chacun déchiffrant avec son propre matériel cryptographique, adossé à un annuaire de clés publiques. À la différence de `--pour`, qui repose sur une vérification par l'instance, cette variante protégerait également contre une instance compromise.
- Libération d'un contenu subordonnée à l'approbation authentifiée d'une seconde identité, appliquée et journalisée par l'instance.

## CONFORMITÉ

Les identifiants d'options (`AUTH-1`, `CHIF-2`, `TTL-2`, `CACHE-1`…) employés dans la configuration et dans la sortie de `--verifier` sont ceux du document d'architecture technique, section « Configurations disponibles ». Les minima applicables aux systèmes relevant de l'II 901 et de l'IGI 1300 y figurent en section « Configurations exigées en contexte réglementé ». La sortie de `ardoise serve --politique` est destinée à être versée telle quelle au dossier d'homologation de l'instance.

## VOIR AUSSI

Document d'architecture technique ardoise.pm — ANSSI-PA-022 v3.0, *Recommandations relatives à l'administration sécurisée des systèmes d'information*, en particulier le chapitre 11 (systèmes d'échanges sécurisés).

## LICENCE

Apache 2.0 assortie de la Commons Clause : usage, modification et redistribution libres ; vente interdite, y compris à l'éditeur.
