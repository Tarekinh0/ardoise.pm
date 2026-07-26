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
ardoise cle --generer [--fichier CHEMIN]
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

**cle --generer**
: Génère une paire de clés X25519 de destinataire pour le chiffrement multi-destinataires (CHIF-MD). La clé privée est écrite dans un fichier aux droits 0600 ; la clé publique, affichée sur la sortie standard, est destinée à l'annuaire de clés de l'entité. Voir `--annuaire` et `--pour`.

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

**--mots**
: Chiffre le contenu avec 5 mots mnémoniques BIP39 français saisis interactivement (CHIF-5, R−). Les mots sont dérivés par Argon2id pour produire une clé AES-256 ; le blob_salt stocké dans l'en-tête assure que deux ardoises avec les mêmes mots ont des clés différentes. Le contenu se récupère avec « ardoise get --mots » et les mêmes mots. Incompatible avec « --pour » uniquement. En mode analysé, le client fournit la clé de chiffrement au serveur (CHIF-5 analysé) ; en mode aveugle, le chiffrement est intégralement local.

**-f**, **--fichier** *CHEMIN*
: Dépose le contenu du fichier indiqué, équivalent à le fournir en argument positionnel.

**-y**, **--sans-confirmation**
: N'interrompt pas le dépôt lorsqu'un secret est détecté dans le contenu (voir `--secrets`). À réserver aux traitements automatisés dont le contenu est maîtrisé. Ne contourne jamais un `bloquer` imposé par l'instance.

La taille de contenu est bornée par l'instance (`contenu.taille_max`, 256 Kio par défaut). Côté client, une borne mémoire dure de 64 Mio est appliquée en toutes circonstances — y compris si une instance mal configurée annoncerait une taille nulle. Le code de retour 8 (« taille dépassée ») est émis dans ce cas.

**--secrets** *MODE*
: Comportement de la détection locale de secrets : `bloquer` (refus du dépôt), `demander` (confirmation interactive, défaut), `signaler` (avertissement sans interruption). L'instance peut imposer `bloquer` et interdire les autres valeurs. Le mode effectif est le plus strict entre le choix local et l'exigence de l'instance.

**--pour** *DESTINATAIRE*[,*DESTINATAIRE*…]
: Restreint la lecture aux identités désignées. Un destinataire est une identité individuelle (`alice.durand`) ou un groupe de l'annuaire de l'entité, préfixé d'une arobase (`@equipe-reseau`). La vérification est appliquée par l'instance : un lecteur non désigné reçoit la même réponse qu'une ardoise inexistante, sans rien apprendre de son existence. Option indisponible sur les instances retenant l'identification déclarative, l'identité du lecteur y étant falsifiable. Sans `--pour`, l'ardoise est au porteur — toute identité authentifiée présentant l'identifiant peut lire.

**--annuaire** *CHEMIN*
: Active le chiffrement multi-destinataires (CHIF-MD, ADR-014 cas a) en complément de `--pour`. L'annuaire est un fichier JSON associant chaque identité de destinataire à sa clé publique X25519 en base64. Lorsque chaque destinataire individuel désigné possède une clé dans l'annuaire, la clé de contenu est enveloppée séparément pour chacun : chaque destinataire ouvre avec sa propre clé privée, sans secret partagé — ce qui protège également contre une instance compromise, contrairement à la vérification serveur seule. Un groupe (`@…`) ou une identité sans clé dans l'annuaire fait retomber sur la seule vérification serveur (avec avertissement). L'identifiant d'une ardoise CHIF-MD porte le fragment `#md` (une sentinelle, jamais une clé) et le destinataire doit disposer de sa clé privée (`cle_privee_ardoise`, `ARDOISE_CLE_PRIVEE`). Surcharge la clé `annuaire` de la configuration client et la variable `ARDOISE_ANNUAIRE`. Voir `ardoise cle --generer`.

**--marquage** *TEXTE*
: Ajoute une mention libre au marquage automatique de l'instance. Ne remplace jamais ce dernier.

## OPTIONS DE RÉCUPÉRATION (get)

**-o**, **--sortie** *CHEMIN*
: Écrit le contenu dans un fichier au lieu de la sortie standard. Le fichier est créé avec les droits 0600 (le contenu restitué n'appartient qu'à son destinataire).

**-n**, **--sans-cache**
: N'utilise pas le cache local et n'y écrit pas, même lorsque l'instance l'autorise.

**--cache-seul**
: Ne contacte pas l'instance et sert exclusivement depuis le cache local. Échoue si l'entrée est absente ou expirée. La politique de cache (CACHE-2 « borne » ou CACHE-3 « libre »), consignée dans l'entrée au moment de l'écriture, gouverne la lecture : une entrée « borne » échue est détruite et n'est jamais servie, même hors ligne.

**--mots**
: Récupère une ardoise déposée avec 5 mots mnémoniques (CHIF-5). Les mots sont saisis interactivement au terminal ; l'identifiant serveur et la clé de chiffrement en sont dérivés. Aucun identifiant n'est passé en argument lorsque cette option est employée : les mots suffisent à retrouver l'ardoise. Incompatible avec l'identifiant standard et « --verifier-empreinte ».

**--verifier-empreinte** *EMPREINTE*
: Compare l'empreinte du contenu chiffré reçu à la valeur fournie et refuse en cas d'écart. Format : 64 caractères hexadécimaux, préfixe `sha256:` admis.

**--argument**
: Lit l'identifiant depuis la ligne de commande plutôt que sur l'entrée standard. Par défaut, l'identifiant est lu sur stdin afin de ne pas apparaître dans les arguments du processus ni dans l'historique du shell (voir **SÉCURITÉ**). Cette option rétablit le passage en argument pour les usages où l'identifiant n'est pas sensible (tests, scripts maîtrisés).


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
: Certificat client et clé privée, pour les instances exigeant une authentification par certificat (AUTH-2, R). Le certificat et la clé sont stockés sur le poste (fichiers aux droits 0600).

**--pkcs11** *URI*
: **Non disponible dans cette version.** L'authentification par certificat sur support matériel (AUTH-1, R+) exigerait le chargement d'un module natif (PKCS#11), incompatible avec la contrainte de binaire 100 % statique du produit. L'option est acceptée et documentée ; à l'exécution, elle produit un message explicite et le code de retour 1. Le certificat logiciel (AUTH-2, `--certificat` et `--cle`) offre une vérification serveur équivalente : la seule différence est la protection de la clé privée côté poste, déjà couverte par le durcissement du poste d'administration (HE-2). Voir le registre des risques pour le suivi de cette limitation.

**--jeton** *CHEMIN*
: Fichier contenant le jeton délivré par le service d'identité de l'entité. Jamais passé en argument littéral.

**--ac** *CHEMIN*
: Autorité de certification à laquelle faire confiance pour valider l'instance. Par défaut : magasin déclaré dans la configuration client.

## FICHIER DE CONFIGURATION DE L'INSTANCE

Format JSON strict : tout champ inconnu est une erreur ; toute option omise prend sa valeur la plus prudente — c'est-à-dire le mécanisme le plus robuste, la borne la plus courte, la surface la plus réduite. Chaque option correspond à un identifiant du document d'architecture, rappelé en commentaire.

```json
{
  "instance": {
    "nom":    "ardoise-adm-zone-reseau",
    "mode":   "aveugle",
    "ecoute": "10.0.12.4:8443"
  },

  "auth": {
    "mecanisme":       "mtls",
    "ac_clients":      "/etc/ardoise/ac-clients.pem",
    "champ_identite":  "CN",
    "jetons":          "",
    "groupes":         ""
  },

  "contenu": {
    "chiffrement": "cle",
    "taille_max":  "256Kio"
  },

  "retention": {
    "support":        "memoire",
    "lecture_unique": "au-choix",
    "duree_max":      "24h",
    "duree_defaut":   "1h",
    "repertoire":     "",
    "cle_magasin":    ""
  },

  "cache": {
    "politique": "interdit"
  },

  "analyse": {
    "secrets_client": "bloquer",
    "icap_url":       "",
    "icap_delai":     "10s",
    "icap_regles":    ""
  },

  "journal": {
    "destination": "syslog+tls://journal.adm.interne:6514",
    "chainage":    true,
    "fichier":     "",
    "ac":          ""
  },

  "transport": {
    "certificat":  "/etc/ardoise/instance.pem",
    "cle":         "/etc/ardoise/instance.key",
    "version_min": "1.3",
    "epinglage":   true
  },

  "marquage": {
    "actif":   true,
    "libelle": "DIFFUSION RESTREINTE"
  }
}
```

**instance** — identité et mode de l'instance.
- `nom` (chaîne) : obligatoire. Identifie l'instance dans les journaux.
- `mode` (chaîne) : `"aveugle"` (défaut, le serveur ne voit jamais le clair) ou `"analyse"` (le serveur analyse avant chiffrement, CHIF-4).
- `ecoute` (chaîne) : adresse d'écoute `hôte:port`. Obligatoire si l'option `--ecoute` n'est pas fournie.

**auth** — mécanisme d'identification (AUTH-1 à AUTH-4, DAT §5.2). Défaut : `"mtls-materiel"` (AUTH-1, R+, le plus robuste — exige `ac_clients`).
- `mecanisme` : `"mtls-materiel"` (AUTH-1, R+), `"mtls"` (AUTH-2, R), `"jeton"` (AUTH-3, R‑), `"declaratif"` (AUTH-4, R‑‑).
- `ac_clients` : chemin du fichier PEM de l'AC des certificats clients. Requis avec `"mtls-materiel"` et `"mtls"` ; refusé avec les autres mécanismes.
- `champ_identite` : `"CN"` (défaut), `"SAN:email"`, `"SAN:dns"` ou `"SAN:uri"`. Champ du certificat client portant l'identité.
- `jetons` : chemin du fichier JSON de la table des jetons (AUTH-3). Associatif `"identité": "SHA-256 en hexadécimal"`. Les jetons eux-mêmes n'y figurent jamais — seules leurs empreintes. Fichier 0600. Requis avec `"jeton"`, refusé sinon. Exemple : `{ "alice.durand": "9f86d081…" }`.
- `groupes` : chemin du fichier JSON de la table des groupes de destinataires (`--pour`). Associatif `"@groupe": ["membre1", "membre2"]`. Refusé sous identification déclarative (AUTH-4), où `--pour` est structurellement inopérant.

En mode `"analyse"`, la source des identités (IGC des certificats, service d'identité des jetons) doit être distincte du SI d'administration (R56, DAT §6.3).

**contenu** — protection des contenus (CHIF-2, CHIF-4, DAT §5.4). Défaut : `"cle"` (CHIF-2, R) en mode aveugle, `"serveur"` (CHIF-4, R‑‑) en mode analysé.
- `chiffrement` : `"cle"` (CHIF-2) ou `"serveur"` (CHIF-4, mode analysé uniquement). Les schémas CHIF-5 (mo5 mnémoniques) et CHIF-MD (multi-destinataires) sont des choix exclusivement client (flags `--mots` et `--annuaire`), jamais des valeurs de configuration serveur. En mode `"analyse"`, seule la valeur `"serveur"` est admise ; en mode `"aveugle"`, `"serveur"` est refusé.
- `taille_max` : taille maximale d'un contenu en notation lisible (`"256Kio"`, `"1Mio"`, `"512o"`). Défaut : `"256Kio"`.

**retention** — conservation et durée de vie (RET-1 à RET-3, TTL-1 à TTL-3, DAT §5.3). Défauts : mémoire vive, lecture unique imposée (RET-1, R+), 1 heure.
- `support` : `"memoire"` (RET-2, défaut) ou `"disque-chiffre"` (RET-3).
- `lecture_unique` : `"imposee"` (RET-1, défaut), `"au-choix"` ou `"interdite"`.
- `duree_max` : durée de vie maximale (`"1h"`, `"24h"`, `"168h"`). Défaut : `"1h"` (TTL-1, R+). Le plafond absolu est 168 h (ADR-003).
- `duree_defaut` : durée de vie appliquée en l'absence de `--duree`. Défaut : la plus petite de 1 h et `duree_max`.
- `repertoire` : emplacement du magasin sur disque. Requis avec `"disque-chiffre"`, refusé avec `"memoire"`. Défaut : `"/var/lib/ardoise"`.
- `cle_magasin` : chemin du fichier contenant la clé du magasin sur disque — 32 octets bruts ou 64 caractères hexadécimaux, droits 0600. Requis avec `"disque-chiffre"`, refusé avec `"memoire"`.

**cache** — rémanence côté client (CACHE-1 à CACHE-3, DAT §5.9, ADR-013). Défaut : `"interdit"` (CACHE-1, R).
- `politique` : `"interdit"` (CACHE-1, aucune rémanence), `"borne"` (CACHE-2, purgé à l'échéance), `"libre"` (CACHE-3, purgé sur demande).

**analyse** — analyse de contenu (ANA-1 à ANA-4, DAT §5.5). Défaut : détection de secrets côté client en mode `"bloquer"`.
- `secrets_client` : `"bloquer"` (défaut), `"demander"`, `"signaler"` ou `"desactive"`. Le client ne peut jamais choisir un mode moins strict que celui déclaré par l'instance.
- `icap_url` : adresse ICAP (`"icap://hôte:port/service"`). Requis en mode `"analyse"` — son absence empêche le démarrage. Refusé en mode `"aveugle"`.
- `icap_delai` : délai total de l'analyse ICAP (`"10s"`, `"30s"`). Défaut : `"10s"`. Au-delà, le dépôt est refusé (fail-closed, non désactivable, ADR-011).
- `icap_regles` : jeu de règles complémentaire de l'entité (ANA-1). Transmis tel quel dans l'en-tête `X-Ardoise-Regles` de la requête ICAP. Chaîne vide : aucune règle supplémentaire.

**journal** — journalisation et imputabilité (JOURN-1 à JOURN-4, DAT §5.6, ADR-005). Défaut : `"aucun"` (JOURN-4). La journalisation ne porte jamais sur les contenus.
- `destination` : `"aucun"` (JOURN-4, défaut), `"fichier"` (JOURN-3), ou une URL `"syslog+tls://hôte:port"` (JOURN-1/JOURN-2).
- `chainage` : active le chaînage cryptographique SHA-256 des entrées (JOURN-1, R+). Défaut : `true` si la destination est un collecteur, `false` sinon. Explicite requis avec `"fichier"` ou `"aucun"`.
- `fichier` : chemin du journal local (JOURN-3). Requis avec la destination `"fichier"`, refusé sinon. Une entrée JSON par ligne, ajout seul, droits 0600.
- `ac` : AC du collecteur syslog+TLS au format PEM (JOURN-1/JOURN-2). Défaut : magasin système du poste. Refusé sans destination de collecte.

**transport** — matériel et version TLS (TLS-2, TLS-3, DAT §5.7). Défaut : TLS 1.3, épinglage actif.
- `certificat`, `cle` : chemin du certificat et de la clé privée de l'instance. Obligatoires — le serveur refuse de démarrer sans matériel TLS.
- `version_min` : `"1.3"` (TLS-2, défaut) ou `"1.2"` (TLS-3). TLS 1.2 restreint les suites à ECDHE + AES-GCM/ChaCha20-Poly1305 (guide ANSSI).
- `epinglage` : si `true` (défaut), seule l'AC déclarée dans `auth.ac_clients` est reconnue — aucune autre autorité, y compris publique.

**marquage** — marquage de sensibilité (MARQ-1, MARQ-2, DAT §5.8). Défaut : actif, libellé obligatoire.
- `actif` : `true` (MARQ-1, défaut) ou `false` (MARQ-2). Lorsqu'il est actif, le libellé est préfixé à chaque contenu restitué.
- `libelle` : texte du marquage (`"DIFFUSION RESTREINTE"`, etc.). Obligatoire lorsque le marquage est actif.

En mode `"analyse"`, une adresse ICAP est obligatoire : son absence empêche le démarrage. Le refus de dépôt en cas de verdict indisponible ou de délai dépassé n'est pas désactivable.

## FICHIER DE CONFIGURATION CLIENT

Format JSON strict, mêmes règles que la configuration d'instance. Les clés `annuaire` et `cle_privee_ardoise` portent le chiffrement multi-destinataires (CHIF-MD, ADR-014).

```json
{
  "endpoint":           "https://ardoise.adm.interne:8443",
  "ac":                 "/etc/pki/ac-interne.pem",
  "certificat":         "/etc/pki/poste.pem",
  "cle":                "/etc/pki/poste.key",
  "pkcs11":             "",
  "jeton":              "",
  "cache":              "~/.cache/ardoise",
  "annuaire":           "",
  "cle_privee_ardoise": ""
}
```

- `endpoint` : URL de l'instance (`https://hôte:port`). Surchargé par `ARDOISE_ENDPOINT` puis par `--endpoint`.
- `ac` : autorité de certification de confiance pour valider l'instance (PEM). Surchargé par `ARDOISE_AC` puis par `--ac`.
- `certificat`, `cle` : certificat client et clé privée (AUTH-2). Surchargés par `ARDOISE_CERTIFICAT`/`ARDOISE_CLE` puis par `--certificat`/`--cle`.
- `pkcs11` : URI du support matériel. **Non disponible en V1** (binaire statique, voir `--pkcs11`). Accepté dans la configuration, refusé à l'exécution.
- `jeton` : chemin du fichier contenant le jeton d'identité (AUTH-3), jamais le jeton lui-même. Surchargé par `ARDOISE_JETON` puis par `--jeton`.
- `cache` : emplacement du cache local. Surchargé par `ARDOISE_CACHE`. Défaut : `~/.cache/ardoise`.
- `annuaire` : chemin de l'annuaire de clés publiques X25519 des destinataires pour le chiffrement multi-destinataires (CHIF-MD). Fichier JSON associant chaque identité à sa clé publique en base64. Surchargé par `ARDOISE_ANNUAIRE` puis par `--annuaire`. Exemple : `{ "alice.durand": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" }`.
- `cle_privee_ardoise` : chemin du fichier contenant la clé privée X25519 du poste pour le déchiffrement multi-destinataires (CHIF-MD). Fichier 0600, 32 octets en base64 ou hexadécimal. Surchargé par `ARDOISE_CLE_PRIVEE`. Généré par `ardoise cle --generer`.

Ce fichier est destiné à être poussé par la télédistribution de l'entité ; l'utilisateur n'a normalement rien à configurer.

## VARIABLES D'ENVIRONNEMENT

| Variable | Rôle |
|---|---|
| `ARDOISE_ENDPOINT` | Instance par défaut |
| `ARDOISE_AC` | Autorité de certification de confiance |
| `ARDOISE_CERTIFICAT`, `ARDOISE_CLE` | Matériel d'authentification par certificat |
| `ARDOISE_PKCS11` | URI du support matériel (non disponible en V1) |
| `ARDOISE_JETON` | Chemin du fichier de jeton (jamais le jeton lui-même) |
| `ARDOISE_ANNUAIRE` | Chemin de l'annuaire de clés publiques (CHIF-MD) |
| `ARDOISE_CLE_PRIVEE` | Chemin de la clé privée X25519 du poste (CHIF-MD) |
| `ARDOISE_CACHE` | Emplacement du cache local |
| `ARDOISE_NO_COLOR` | Désactive la colorisation |

## FICHIERS

| Chemin | Rôle |
|---|---|
| `/etc/ardoise/ardoise.json` | Configuration de l'instance |
| `/etc/ardoise/client.json` | Configuration client à l'échelle du poste |
| `~/.config/ardoise/client.json` | Configuration client de l'utilisateur |
| `~/.cache/ardoise/` | Cache local, si l'instance l'autorise |
| `/var/lib/ardoise/` | Magasin sur support, si `support = "disque-chiffre"` |
| `/etc/ardoise/ac-clients.pem` | AC des certificats clients (mTLS) |
| `/etc/ardoise/jetons.json` | Table des jetons (AUTH-3) |
| `/etc/ardoise/groupes.json` | Table des groupes de destinataires (`--pour`) |
| `/etc/ardoise/magasin.cle` | Clé de chiffrement du magasin sur disque (RET-3) |

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

Adresser un extrait à une personne, puis à une équipe :

```
$ ardoise --pour alice.durand < incident.log
$ journalctl -u nginx -n 100 | ardoise --pour @equipe-reseau,rssi -t 4h
```

Adresser un extrait avec chiffrement multi-destinataires (CHIF-MD) :

```
$ ardoise --pour alice.durand,bruno.marchal --annuaire /etc/ardoise/annuaire.json < incident.log
Aucune clé publique pour « bruno.marchal » dans l'annuaire : désignation appliquée par l'instance seule, sans chiffrement multi-destinataires
a7f3k9x2#md
```

Ici, `alice.durand` possède une clé dans l'annuaire (son enveloppe est chiffrée pour sa clé publique) mais `bruno.marchal` n'en possède pas — la vérification serveur s'applique pour lui. L'identifiant porte `#md`, la sentinelle qui signale au client de récupération qu'aucune clé symétrique n'est attendue.

Générer le matériel de destinataire et publier la clé :

```
$ ardoise cle --generer --fichier ~/.config/ardoise/ma-cle-privee
Clé privée écrite dans /home/alice/.config/ardoise/ma-cle-privee (0600). La clé publique ci-dessous rejoint l'annuaire de l'entité :
hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=
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
# ardoise serve --config /etc/ardoise/ardoise.json --verifier
Politique effective :
  Identification    AUTH-2  (R)    certificat client, AC interne
  Contenu           CHIF-2  (R)    clé aléatoire par ardoise, chiffrement local
  Conservation      RET-2   (R)    mémoire vive
  Durée de vie      TTL-2   (R)    24h maximum
  Rémanence client  CACHE-1 (R)    interdite
  Analyse           ANA-3   (R‑)   détection de secrets côté client
  Journalisation    JOURN-1 (R+)   collecteur central, entrées chaînées
  Transport         TLS-2   (R)    TLS 1.3, épinglage actif
  Marquage          MARQ-1  (R)    « DIFFUSION RESTREINTE »
Configuration conforme aux minima II 901. Aucune incohérence détectée.
```

## SÉCURITÉ

**L'identifiant contient la clé — sauf en CHIF-MD.** Tout ce qui suit le caractère `#` dans un identifiant standard est le matériel de déchiffrement ; il ne parvient jamais à l'instance. Un identifiant complet équivaut au contenu : il se transmet par un canal maîtrisé, ne se colle pas dans un outil de tickets, une messagerie externe ou un compte rendu. **Exception :** un identifiant portant le fragment `#md` est une ardoise multi-destinataires (CHIF-MD) — le fragment est une sentinelle, jamais une clé ; le déchiffrement exige la clé privée X25519 du destinataire (`cle_privee_ardoise`, `ARDOISE_CLE_PRIVEE`).

**Sans destinataire désigné, l'ardoise est au porteur.** Toute identité authentifiée présentant l'identifiant peut lire. L'option `--pour` ajoute une seconde condition — être le destinataire désigné — de sorte qu'un identifiant intercepté ne suffise plus. Sans `--annuaire`, cette vérification est purement serveur : elle protège contre un tiers, non contre une instance compromise. Avec `--annuaire` et le chiffrement multi-destinataires (CHIF-MD), la clé de contenu est enveloppée sous la clé publique de chaque destinataire — l'instance elle-même ne peut pas lire, même en mode analysé.

**Les arguments de ligne de commande sont visibles.** Sur une machine partagée, `ps` expose les arguments des processus des autres utilisateurs, et l'historique du shell conserve les commandes. Préférez `ardoise get -` avec l'identifiant sur l'entrée standard.

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

La fonction suivante est implémentée ; la seconde est à l'étude pour une version ultérieure.

- **Chiffrement multi-destinataires (CHIF-MD, ADR-014 cas a) — implémenté.** La clé de contenu est enveloppée une fois par destinataire au moyen de sa clé publique X25519, publiée dans un annuaire de l'entité. Chaque destinataire ouvre avec sa propre clé privée, sans secret partagé. Activé par `--annuaire` en complément de `--pour`. L'identifiant porte le fragment `#md` (sentinelle, jamais une clé). La génération du matériel de destinataire se fait avec `ardoise cle --generer`. Voir `--annuaire` et `cle_privee_ardoise`.
- **Libération sous double approbation (ADR-014 cas b) — à l'étude.** Libération d'un contenu subordonnée à l'approbation authentifiée d'une seconde identité, appliquée et journalisée par l'instance.

## CONFORMITÉ

Les identifiants d'options (`AUTH-1`, `CHIF-2`, `TTL-2`, `CACHE-1`…) employés dans la configuration et dans la sortie de `--verifier` sont ceux du document d'architecture technique, section « Configurations disponibles ». Les minima applicables aux systèmes relevant de l'II 901 et de l'IGI 1300 y figurent en section « Configurations exigées en contexte réglementé ». La sortie de `ardoise serve --politique` est destinée à être versée telle quelle au dossier d'homologation de l'instance.

L'option `--verifier` et la sortie de `ardoise serve --politique` lisent la configuration effective — défauts prudents appliqués — et non le fichier brut. C'est cette politique effective qui fait foi pour l'homologation.
## DISTRIBUTION ET VÉRIFICATION

Le binaire signé, sa signature détachée Ed25519, la clé publique et le SBOM SPDX sont publiés dans chaque archive de release. Le script `verifier.sh`, fourni dans l'archive, contrôle l'intégrité du binaire hors ligne — sans aucune connexion réseau — en trois étapes :

1. Vérification de l'empreinte SHA-256 du binaire contre l'empreinte de référence gravée dans le script.
2. Vérification de la signature détachée Ed25519 (`ardoise.sig`) avec la clé publique (`ardoise.pub`).
3. Résumé du SBOM au format SPDX (`ardoise.spdx.json`).

Le script exige OpenSSL 3.0+ (ou LibreSSL) et fonctionne sur toute station d'administration durcie. Toute divergence bloque l'exécution : le binaire ne doit pas être exécuté sans vérification d'intégrité préalable.


## VOIR AUSSI

Document d'architecture technique ardoise.pm — ANSSI-PA-022 v3.0, *Recommandations relatives à l'administration sécurisée des systèmes d'information*, en particulier le chapitre 11 (systèmes d'échanges sécurisés).

## LICENCE

Apache 2.0 assortie de la Commons Clause : usage, modification et redistribution libres ; vente interdite, y compris à l'éditeur.
