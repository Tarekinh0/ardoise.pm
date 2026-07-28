# ardoise.pm

Service interne d'échange éphémère de texte pour équipes d'administration.

## À quoi ça sert

Les administrateurs s'échangent des fragments de texte toute la journée : extraits
de journaux, portions de configuration, commandes à faire relire. Faute d'outil
interne, ces contenus finissent sur des pastebins publics — indexés et collectés par
des tiers — ou transitent par des canaux de contournement (transfert vers la
bureautique) qui échappent au périmètre de sécurité du SI d'administration.

**ardoise** referme cette brèche : un binaire Go unique qui dépose et récupère des
blocs de texte sur une instance maîtrisée. Le contenu est chiffré, horodaté, et
détruit à échéance. Aucune archive, aucun listage, aucune recherche.

Ce n'est **ni un coffre-fort de secrets, ni un serveur de fichiers, ni une archive** :
une ardoise s'écrit une fois, se lit, puis disparaît.

## Ce qui le distingue

- **Éphémère par construction** — chaque ardoise a une durée de vie ; aucune option ne
  permet la conservation illimitée.
- **Autodestruction à la première lecture** (au choix de l'émetteur, ou imposée par l'instance).
- **Aucun compte, aucun listage, aucune recherche** — lister reviendrait à constituer
  l'inventaire que le produit refuse de tenir.
- **Chiffrement de bout en bout** en mode aveugle — la clé vit dans l'identifiant, côté
  client, et ne parvient jamais au serveur.
- **Journalisation des actes, jamais des contenus** — métadonnées seules, chaînage optionnel.
- **Binaire unique, hors-ligne** — client et serveur dans le même exécutable statique,
  builds signés et reproductibles.

## Les deux modes

Le mode est une propriété de l'instance : le client l'affiche avant tout envoi et ne
peut jamais l'affaiblir.

| Mode | Le serveur voit-il le clair ? | Quand l'utiliser |
|---|---|---|
| **Aveugle** | Jamais. Chiffrement sur le poste émetteur. | Les deux extrémités sont déjà dans la zone d'administration de confiance. **Exigé en contexte classifié (IGI 1300).** |
| **Analysé** | Le temps de l'analyse imposée. | Le texte franchit une frontière de zone (bureautique → administration) et la politique impose l'inspection de tout contenu (ANSSI R58). |

> ⚠️ **Le mode analysé n'est pas un chiffrement de bout en bout.** L'instance accède au
> contenu en clair pendant l'analyse. Le client l'indique avant chaque dépôt : en mode
> analysé, la première ligne devient
> `ardoise : Instance : <nom> (mode analysé — le serveur accède au contenu en clair pendant l'analyse)`.

## Cas d'usage

Les lignes d'information (politique, marquage, durée) sont écrites sur **stderr** ;
l'identifiant et le contenu restitué vont sur **stdout** — d'où la composition propre
avec des tubes Unix. Les sorties ci-dessous sont celles réellement émises par le binaire.

### 1. Déposer et partager un extrait de journal

```console
$ tail -n 200 /var/log/nginx/error.log | ardoise -t 30m -b
Instance : ardoise-adm-zone-reseau (mode aveugle, chiffrement local)
Marquage : DIFFUSION RESTREINTE
Durée    : 30m — destruction à la première lecture
ny7kxibdkni2#J7xwf_Zc3aEuUn35gn3WZK8y38zQ40RrVLPYPoE_O9k
```

Le contenu est chiffré localement puis déposé ; la dernière ligne (stdout) est
l'**identifiant** à transmettre. `-t 30m` fixe la durée de vie, `-b` détruit le contenu
à la première lecture.

### 2. Récupérer un contenu

Par défaut, `get` lit l'identifiant sur **l'entrée standard** (pour ne pas l'exposer
dans `ps` ni l'historique du shell sur un poste partagé) :

```console
$ ardoise get - < identifiant.txt
=== DIFFUSION RESTREINTE ===
10.0.0.4 - GET /admin 500
10.0.0.7 - GET /admin 500
```

Le marquage de l'instance est préfixé automatiquement. Pour passer l'identifiant en
argument, il faut l'expliciter avec `--argument` :

```console
$ ardoise get --argument ny7kxibdkni2#J7xwf_Zc3aEuUn35gn3WZK8y38zQ40RrVLPYPoE_O9k
```

Le contenu brut étant écrit sur stdout, il se compose directement — par exemple pour
vérifier la syntaxe d'un script sans l'exécuter :

```console
$ ardoise get - < id.txt | sh -n
```

Une ardoise en lecture unique déjà consommée (ou expirée, ou inexistante) renvoie la
même réponse, pour ne rien livrer par recoupement :

```console
$ ardoise get --argument ny7kxibdkni2#J7xwf...
ardoise : ardoise inexistante, expirée ou déjà consommée   # (code de sortie 5)
```

### 3. Restreindre la lecture à une personne ou un groupe

Sans destinataire, « l'ardoise est au porteur » : quiconque authentifié détenant
l'identifiant peut lire. Avec `--pour`, la lecture est réservée aux identités désignées ;
un lecteur non désigné reçoit la même réponse qu'une ardoise inexistante.

```console
$ ardoise --pour alice.durand < incident.log
$ journalctl -u nginx -n 100 | ardoise --pour @equipe-reseau,rssi -t 4h
```

### 4. Inspecter la politique d'une instance avant de déposer

`info` ne dépose rien et ne consomme aucune ardoise : il restitue la configuration
effective de l'instance visée.

```console
$ ardoise info -e https://ardoise.adm.interne:8443
Instance             : ardoise-adm-zone-reseau
Mode                 : aveugle (le serveur ne peut à aucun moment lire les contenus)
Identification       : identification déclarative, non authentifiée (AUTH-4)
Durée de vie         : 24h maximum, 1h par défaut
Taille maximale      : 256 Kio
Lecture unique       : au choix de l'émetteur
Analyse de contenu   : détection de secrets côté client
Rémanence locale     : interdite
Journalisation       : aucune journalisation
Marquage             : DIFFUSION RESTREINTE
```

### 5. Le client refuse de déposer un secret

La détection de secrets tourne côté client, avant tout envoi. Sur un terminal,
`ardoise` liste les occurrences et demande confirmation
(`Poursuivre le dépôt malgré N secret(s) détecté(s) ? [o/N]`). Sans terminal (dans un
script), le dépôt est interrompu :

```console
$ printf 'aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' | ardoise
ardoise : secret détecté : secret, ligne 1 (« wJal… »)
ardoise : dépôt interrompu : aucun terminal disponible pour confirmer   # (code de sortie 4)
```

Un authentifiant relève d'un coffre-fort de mots de passe, pas d'une ardoise.

### 6. Récupérer par 5 mots mnémoniques

Quand l'identifiant complet ne peut pas être transmis par copier-coller (dictée
téléphonique, saisie manuelle), le schéma à 5 mots BIP39 prend le relais :

```console
$ echo "code de rappel astreinte" | ardoise --mots
Instance : ardoise-adm-zone-reseau (mode aveugle, chiffrement local)
Marquage : DIFFUSION RESTREINTE
Durée    : 1h
cercle-gestuel-ethnie-carbone-aviser
```

```console
$ ardoise get --mots
Mots : cercle-gestuel-ethnie-carbone-aviser
code de rappel astreinte
```

### 7. Purger le cache local

```console
$ ardoise purge --tout
Cache local : 0 entrée(s) supprimée(s), 0 conservée(s).
```

Sans `--tout`, seules les entrées expirées sont supprimées. Le cache ne contient que du
chiffré, jamais de clé.

### 8. (Avancé) Générer du matériel de destinataire

Pour participer au chiffrement multi-destinataires (la clé de contenu est enveloppée
sous la clé publique X25519 de chaque destinataire) :

```console
$ ardoise cle --generer --fichier alice.cle
Clé privée écrite dans alice.cle (0600). La clé publique ci-dessous rejoint l'annuaire de l'entité :
Yy14rGH9zKBnpt/Hqd6B552ZXPoS3Jw7wQdNlBTmd3Q=
```

Une clé privée existante n'est jamais écrasée.

## Comprendre l'identifiant

Un identifiant a la forme `<id>#<clé>` :

```
ny7kxibdkni2 # J7xwf_Zc3aEuUn35gn3WZK8y38zQ40RrVLPYPoE_O9k
└─ id serveur ┘ └─ clé de déchiffrement ──────────────────┘
```

L'id serveur fait 12 caractères (`a-z`, `2-9`). Le fragment après le `#` est la **clé** :
elle n'est **jamais transmise au serveur**. Un identifiant complet équivaut donc au
contenu — il se transmet par un canal maîtrisé. En multi-destinataires, le fragment vaut
`#md` : une sentinelle, pas une clé.

## Codes de sortie

Pour scripter autour de `ardoise` :

| Code | Signification |
|---|---|
| 0 | Succès |
| 2 | Erreur d'usage |
| 3 | Option refusée par la politique de l'instance |
| 4 | Dépôt interrompu : secret détecté dans le contenu |
| 5 | Ardoise inexistante, expirée ou déjà consommée |
| 6 | Authentification refusée |
| 7 | Analyse de contenu défavorable ou indisponible |
| 8 | Taille maximale dépassée |
| 9 | Instance injoignable |

## Déploiement d'une instance

```console
$ ardoise serve --config /etc/ardoise/ardoise.json
instance « ardoise-adm-zone-reseau » : écoute sur https://127.0.0.1:8443 (mode aveugle)
```

### Vérifier une configuration — et sa conformité II 901

`serve --verifier` analyse la configuration, affiche chaque option avec son identifiant
et son niveau ANSSI (`R+`, `R`, `R-`, `R--`), **conclut d'emblée sur la conformité aux
minima de l'II 901**, signale toute incohérence, puis rend la main sans démarrer le
service :

```console
$ ardoise serve --config /etc/ardoise/ardoise.json --verifier
Politique effective :
  Identification    AUTH-2   (R)   certificat client, AC interne
  Contenu           CHIF-2   (R)   clé aléatoire par ardoise, chiffrement local
  Conservation      RET-2    (R)   mémoire vive
  Durée de vie      TTL-2    (R)   24h maximum
  Rémanence client  CACHE-1  (R)   interdite
  Analyse           ANA-3    (R-)  détection de secrets côté client
  Journalisation    JOURN-1  (R+)  collecteur central, entrées chaînées
  Transport         TLS-2    (R)   TLS 1.3, épinglage actif
  Marquage          MARQ-1   (R)   « DIFFUSION RESTREINTE »
Configuration conforme aux minima II 901. Aucune incohérence détectée.
```

Une configuration en deçà des minima est refusée avec le détail des écarts (code de
sortie 1) :

```console
$ ardoise serve --config ./labo.json --verifier
Politique effective :
  Identification    AUTH-4   (R--) identification déclarative, non authentifiée
  ...
  Transport         TLS-3    (R-)  TLS 1.2
  Marquage          MARQ-2   (R--) aucun marquage
Configuration NON conforme aux minima II 901 :
  - identification : AUTH-4 (déclarative) sous le minimum AUTH-3
  - journalisation : JOURN-4 sous le minimum JOURN-2 (collecteur central, R46/R47)
  - transport : TLS-3 (TLS 1.2) sous le minimum TLS-2 (TLS 1.3, R24)
  - marquage : MARQ-2 sous le minimum MARQ-1 (marquage automatique)
  - rémanence client : CACHE-3 exclue (CACHE-1 exigé, CACHE-2 admissible)
Aucune incohérence détectée.
```

### Conteneur

```console
$ docker run -v /etc/ardoise:/etc/ardoise:ro ardoise:latest
```

Image OCI sur Red Hat UBI micro, non-root, système de fichiers racine en lecture seule,
`CAP_DROP ALL`.

## Schémas de chiffrement

| Schéma | Octet | Principe |
|---|---|---|
| **CHIF-2** | `0x01` | Clé AES-256 aléatoire, portée par l'identifiant (`id#cle`) |
| **CHIF-4** | `0x04` | Chiffrement par le serveur après verdict d'analyse (mode analysé) |
| **CHIF-5** | `0x06` | 5 mots BIP39 + Argon2id (`--mots`) |
| **CHIF-MD** | `0x05` | Multi-destinataires, enveloppe X25519 par destinataire |

Chiffrement authentifié AES-256-GCM, clé unique par ardoise. Détails complets :
[`docs/dat.md`](docs/dat.md) annexe B.

## Conformité

ardoise est conçu pour être déployé depuis un réseau d'administration standard jusqu'aux
environnements relevant de l'**II 901** (Diffusion Restreinte) et de l'**IGI 1300** (SI
classifiés). La configuration de chaque instance s'aligne sur les identifiants d'options
du guide **ANSSI-PA-022**, et `serve --verifier` (ci-dessus) rend un verdict de
conformité II 901 versable à un dossier d'homologation. Voir [`docs/dat.md`](docs/dat.md)
§5 et §6.

## Installation et vérification

Paquets signés, builds reproductibles, installation hors ligne native.

```console
$ ardoise version
ardoise 1.0.0
Empreinte du binaire       : sha256:10d63df4afa37d1397fcb5669bd15df7120b47970ed10edc2bae985e30e61c2b
Identifiant de compilation : 2026-07-24-a71c3d7
```

Le script [`verifier.sh`](verifier.sh) valide l'intégrité d'un binaire hors ligne.
Manuel complet : [`docs/man.md`](docs/man.md).

## Licence

Apache 2.0 + Commons Clause — usage, modification et redistribution libres ; vente
interdite. Voir [ADR-012](docs/dat.md).

