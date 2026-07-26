# ardoise.pm — Document d'Architecture Technique

| | |
|---|---|
| **Produit** | ardoise.pm — service interne d'échange éphémère de texte |
| **Statut** | Brouillon — v0.2 |
| **Référentiels** | ANSSI-PA-022 v3.0 (11/05/2021), II 901, IGI 1300 |
| **Licence** | Apache 2.0 + Commons Clause — source disponible, vente interdite (ADR-012, sous réserve de validation juridique) |

---

## 1. Objet

Ce document décrit l'architecture technique d'ardoise.pm, un service d'échange éphémère de blocs de texte destiné aux équipes d'administration de systèmes d'information. Il recense les exigences issues des référentiels applicables, décrit l'architecture retenue, énumère les configurations disponibles et celles exigées en contexte réglementé, établit la matrice de couverture des recommandations du guide ANSSI-PA-022, et consigne les décisions d'architecture sous forme d'ADR (Architecture Decision Records).

## 2. Contexte et besoin

Les administrateurs échangent quotidiennement des fragments de texte : extraits de journaux, portions de configuration, commandes à faire relire. En l'absence d'outil interne, cet usage se reporte sur des services publics de type pastebin, dont les contenus sont indexés et collectés par des tiers, ou sur des canaux de contournement (transfert vers l'environnement bureautique) échappant au périmètre de sécurité du SI d'administration.

Le guide ANSSI-PA-022 encadre l'administration sécurisée des SI. Il interdit tout accès à Internet depuis les postes d'administration (R10) et prévoit des systèmes d'échanges sécurisés (chapitre 11). Le serveur pastebin y est mentionné comme composant possible du système d'échange (section 11.2, encart d'information, p. 47, ajouté en v3.0). Ardoise vise à fournir une implémentation de ce composant, déployable depuis les environnements courants jusqu'à ceux relevant de l'II 901 (Diffusion Restreinte) et de l'IGI 1300 (SI classifiés).

## 3. Exigences

### 3.1 Exigences fonctionnelles

| ID | Exigence |
|---|---|
| EF-1 | Déposer un bloc de texte et obtenir en retour un identifiant de récupération. |
| EF-2 | Récupérer un bloc de texte à partir de son identifiant, sur la sortie standard (composable en shell). |
| EF-3 | Toute ardoise porte une durée de vie ; l'expiration entraîne la destruction du contenu. |
| EF-4 | Option de destruction à la première lecture. |
| EF-5 | Utilisation nominale en une commande, sans configuration côté utilisateur (endpoint fourni par l'environnement). |

### 3.2 Exigences de sécurité

| ID | Exigence | Origine |
|---|---|---|
| ES-1 | Aucun stockage permanent côté serveur ; suppression dès transfert effectif ou à l'expiration de la durée de vie. Toute rémanence côté client est bornée par l'échéance et soumise à autorisation de l'instance (§5.9). | R57 |
| ES-2 | Seules des opérations de transfert sont exposées ; aucune session de travail ne peut être ouverte via le service. | R54 |
| ES-3 | Le contenu est chiffré avant mise à disposition ; en mode aveugle, le serveur ne peut à aucun moment lire les contenus. | Analyse de risque produit |
| ES-4 | La configuration de sécurité est déclarée et imposée par l'instance serveur ; le client s'y conforme, ne peut pas l'affaiblir, et affiche à l'utilisateur le mode et les options actives avant tout envoi. | Analyse de risque produit |
| ES-5 | Flux protégés par TLS ; prise en charge des autorités de certification internes. | R24 |
| ES-6 | Une instance par zone d'administration ; aucune liaison entre instances. | R22, §13.2 |
| ES-7 | Chaque opération est rattachée à une identité, selon le mécanisme déclaré par l'instance (§5.1). En mode analysé, les identités et secrets employés ne proviennent jamais du SI d'administration. | R36, R37, R56 |
| ES-8 | Lorsqu'elle est activée, la journalisation porte sur les métadonnées d'imputabilité — jamais sur les contenus — et consigne le mécanisme d'identification employé. | R31, R46, R47 |
| ES-9 | Installation hors ligne possible à partir de paquets signés vérifiables localement ; aucune dépendance réseau à l'exécution ; builds reproductibles. | R13, R42, R43, §13.5 |
| ES-10 | Taille maximale de contenu imposée par l'instance (le service n'est pas un serveur de fichiers). | R52 |
| ES-11 | Marquage automatique du niveau de sensibilité de l'instance en tête de chaque contenu restitué, lorsque le marquage est activé. | II 901 (marquage DR) |
| ES-12 | Détection de secrets (clés privées, jetons, mots de passe) côté client, avec alerte locale à l'utilisateur ; aucune remontée. | Analyse de risque produit |

### 3.3 Hypothèses d'environnement

| ID | Hypothèse | Origine |
|---|---|---|
| HE-1 | L'instance est déployée sur le réseau d'administration — ou en coupure entre SI d'administration et SI bureautique en mode analysé — derrière le filtrage de l'entité. | R15/R15-, R16 |
| HE-2 | Les postes clients sont des postes d'administration gérés et durcis par l'entité. | Chapitre 4 (R8–R14) |
| HE-3 | Le client ardoise est distribué par le processus de validation et de télédistribution des outils d'administration de l'entité. | R13 |
| HE-4 | L'accès au service est restreint aux postes et utilisateurs en ayant le besoin opérationnel (filtrage réseau, contrôle d'accès). | R55 |
| HE-5 | En cas de virtualisation, le socle physique est dédié aux infrastructures d'administration. | R7 |
| HE-6 | L'entité dispose des moyens correspondant aux options qu'elle retient : IGC pour l'authentification par certificat, service d'identité pour l'authentification par jeton, chaîne d'analyse exposant une interface ICAP en mode analysé, collecteur de journaux pour l'imputabilité centralisée. | R37, R46, R58 |

## 4. Architecture

### 4.1 Vue d'ensemble

Ardoise est un binaire unique (Go, compilation statique, sans dépendance à l'exécution) portant les deux rôles :

- **Serveur** (`ardoise serve`) : expose deux opérations HTTP — dépôt et récupération — applique la configuration déclarée par l'instance, gère le cycle de vie des ardoises (durée de vie, destruction à la lecture), émet le cas échéant les métadonnées de journalisation.
- **Client** (`ardoise push` / `ardoise get`) : chiffre le contenu côté poste avant envoi lorsque le mode le prévoit, exécute la détection de secrets, affiche la configuration de l'instance cible avant tout envoi, restitue le contenu déchiffré sur la sortie standard.

### 4.2 Modèle de données

Aucune base de données. Le serveur maintient un magasin éphémère d'objets `{identifiant, contenu chiffré, échéance, options}`. Le support de conservation (mémoire vive ou disque chiffré) est une option de configuration (§5.3). L'expiration est garantie par le serveur indépendamment de toute action client.

### 4.3 Identifiants et clés

En mode aveugle, le client génère une clé de chiffrement aléatoire par ardoise ; l'identifiant remis à l'émetteur est composé de l'identifiant serveur et du matériel de clé, ce dernier ne transitant jamais vers le serveur. En schéma CHIF-5 (mots mnémoniques), la clé est dérivée des mots par Argon2id côté client, avec un blob_salt HKDF pour diversifier la clé par ardoise (annexe B). Le serveur retourne l'empreinte du contenu chiffré ; le client la vérifie à la récupération.

### 4.4 Configuration d'instance

Chaque instance est définie par un fichier de configuration unique. Celui-ci déclare le **mode** (§4.5) et, pour chaque dimension de sécurité, l'**option retenue** parmi celles énumérées au §5. Le serveur fait respecter cette configuration ; le client l'interroge avant tout envoi, l'affiche à l'utilisateur, et ne dispose d'aucun moyen de l'affaiblir. La configuration est un artefact signé, versé au dossier d'homologation de l'entité.

### 4.5 Modes de déploiement

Le produit expose **deux modes**, correspondant aux deux positions que le guide distingue pour un système d'échange. Ils se différencient par une seule question : le serveur peut-il, ou non, accéder au contenu.

- **Mode aveugle** — l'instance est une infrastructure d'administration interne, sans interconnexion avec d'autres SI (§11.1, R53). Le contenu est chiffré sur le poste émetteur ; le serveur ne peut à aucun moment le lire. R54–R58 sont sans objet. Aucune option ne permet de lever cette cécité.
- **Mode analysé** — l'instance est positionnée en coupure entre le SI bureautique et le SI d'administration (§11.2, figure 11.1). Les recommandations R54 à R58 s'appliquent. Le contenu est soumis à la chaîne d'analyse de l'entité avant toute mise à disposition (ADR-004, ADR-011), puis chiffré avec une clé remise à l'émetteur et effacée du serveur.

Le mode découle de la position de l'instance dans l'architecture, elle-même déterminée par le découpage en zones de confiance de l'entité (R5). Une instance dessert une zone et une seule (ADR-006), conformément à R22 et aux contraintes de non-mutualisation du §13.2 — en particulier l'interdiction de toute mutualisation entre SI de classifications différentes au sens de l'IGI 1300. Le mode analysé n'a pas vocation à interconnecter un SI classifié : une telle passerelle relève de produits agréés et d'une homologation spécifique (§13.5), hors périmètre du produit.

## 5. Configurations disponibles

### 5.1 Convention de lecture

Les options de configuration sont graduées selon la convention du guide ANSSI-PA-022 (§1.3), afin que le choix d'un déploiement se lise dans le même vocabulaire que le référentiel qui l'encadre :

- **R** — option à l'état de l'art ;
- **R‑** — alternative de premier niveau, d'un niveau de sécurité moindre ;
- **R‑‑** — alternative de second niveau, d'un niveau de sécurité moindre encore ;
- **R+** — option de renforcement complémentaire, destinée aux entités matures.

Le produit n'impose par lui-même aucun niveau : il rend chaque option explicite, la fait respecter par le serveur, et la consigne dans la configuration signée. Les minima applicables en contexte réglementé sont énoncés au §6. Hors de ces contextes, le choix relève de l'analyse de risque de l'entité (R4) et de son autorité d'homologation.

### 5.2 Identification et authentification

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| AUTH-1 | **R+** | Certificat client (mTLS) individuel, porté par un support matériel (carte à puce, jeton FIDO), adossé à l'IGC de l'entité | Aligné sur R36 (double facteur) et R37 (certificats de confiance). Suppose une IGC et un parc de supports. |
| AUTH-2 | **R** | Certificat client (mTLS) individuel, adossé à l'IGC de l'entité | Aligné sur R37. Suppose une IGC déployée jusqu'aux postes d'administration. |
| AUTH-3 | **R‑** | Jeton individuel délivré par l'annuaire ou le service d'identité de l'entité | Pour les entités sans IGC poste. Imputabilité individuelle conservée ; robustesse moindre qu'un certificat. |
| AUTH-4 | **R‑‑** | Identification déclarative (utilisateur et hôte transmis par le client, non vérifiés) | Réservée aux instances en mode aveugle sur réseau d'administration cloisonné et filtré, où l'accès réseau tient lieu de contrôle. L'identité n'est pas authentifiée : les journaux la consignent comme déclarative (ADR-005), et elle ne fonde aucune imputabilité opposable. |

### 5.3 Conservation et durée de vie

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| RET-1 | **R+** | Mémoire vive exclusivement, avec destruction à la première lecture imposée par l'instance | Aucune persistance, aucune seconde lecture possible. Contenus perdus au redémarrage du service — comportement assumé. |
| RET-2 | **R** | Mémoire vive exclusivement ; destruction à la première lecture au choix de l'émetteur | Option nominale. |
| RET-3 | **R‑** | Disque chiffré, effacement à l'échéance | Pour les instances devant survivre à un redémarrage. Introduit une persistance temporaire sur support. |
| TTL-1 | **R+** | Durée de vie maximale ≤ 1 heure | Réduit la fenêtre d'exposition d'un identifiant intercepté. |
| TTL-2 | **R** | Durée de vie maximale ≤ 24 heures | Aligné sur le délai cité par R57. |
| TTL-3 | **R‑** | Durée de vie maximale ≤ 7 jours | Hors contexte réglementé uniquement : au-delà de 24 h, R57 n'est plus couverte. |

Aucune option ne permet la conservation illimitée : la durée de vie est une propriété structurelle du produit (ADR-003).

### 5.4 Protection des contenus

Le tableau ci-dessous recense les schémas de protection. CHIF-1 (clé aléatoire + mot de passe, deux secrets) et CHIF-3 (clé dérivée d'un mot de passe seul) ont été retirés en V1 : CHIF-5 (mots mnémoniques) offre une alternative sans matériel de clé persistant côté émetteur, avec une entropie maîtrisée de 55 bits (5 mots × 11 bits).

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| CHIF-2 | **R** | Chiffrement côté client par clé aléatoire à usage unique | Option nominale du mode aveugle. |
| CHIF-4 | **R‑‑** | Chiffrement par le serveur après analyse, clé remise à l'émetteur puis effacée (cécité a posteriori) | Propre au mode analysé, où R58 impose l'accès au contenu. Le serveur voit le clair pendant la fenêtre d'analyse (annexe A.3). |
| CHIF-5 | **R−** | 5 mots mnémoniques BIP39 français, dérivés côté client par Argon2id (sel fixe) puis HKDF avec blob_salt variable | Alternative au mode aveugle sans matériel de clé persistant : les mots remplacent la clé aléatoire. Incompatible avec le mode analysé (CHIF-4). Incompatible avec « --pour ». |

### 5.5 Analyse de contenu

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| ANA-1 | **R+** | Analyse ICAP synchrone bloquante, complétée des règles propres à l'entité (signatures, YARA, bac à sable) et de la détection de secrets côté client | Couvre R58 et le risque de fuite de secrets. |
| ANA-2 | **R** | Analyse ICAP synchrone bloquante, en refus de dépôt si le verdict n'est pas obtenu (*fail-closed*) | Couverture de R58. Réservé au mode analysé. |
| ANA-3 | **R‑** | Détection de secrets côté client uniquement, avec alerte locale | Option nominale du mode aveugle, où R58 est sans objet. |
| ANA-4 | **R‑‑** | Aucune analyse | Instances en mode aveugle sur zone à faible sensibilité, hors contexte réglementé. |

Le produit n'embarque aucun moteur d'analyse : il soumet et attend un verdict (ADR-011). La pertinence des verdicts relève de la chaîne d'analyse de l'entité.

### 5.6 Journalisation et imputabilité

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| JOURN-1 | **R+** | Métadonnées d'imputabilité émises vers la zone de journalisation dédiée, avec chaînage cryptographique des entrées | Détection de toute altération ou suppression d'entrée. |
| JOURN-2 | **R** | Métadonnées d'imputabilité émises vers la zone de journalisation dédiée de l'entité | Aligné sur R46 et R47. |
| JOURN-3 | **R‑** | Métadonnées conservées localement, collecte périodique | Journal exposé à l'administrateur de l'instance : imputabilité affaiblie. |
| JOURN-4 | **R‑‑** | Aucune journalisation | Déploiements sans exigence d'imputabilité. Aucune investigation possible a posteriori. |

Quelle que soit l'option, la journalisation ne porte jamais sur les contenus (ADR-005).

### 5.7 Transport et distribution

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| TLS-1 | **R+** | TLS 1.3 avec épinglage de l'autorité de certification interne ; flux encapsulés dans un tunnel IPsec lorsqu'ils traversent un réseau non maîtrisé | Aligné sur R21 et R24. |
| TLS-2 | **R** | TLS 1.3, autorité de certification interne | Aligné sur R24 et le guide TLS de l'ANSSI. |
| TLS-3 | **R‑** | TLS 1.2 | Compatibilité avec des équipements anciens ; en deçà de l'état de l'art. |
| DIST-1 | **R** | Paquets signés, empreintes publiées, builds reproductibles, installation intégralement hors ligne | Aligné sur R13, R42, R43 et §13.5. Mode nominal, y compris hors environnement isolé. |
| DIST-2 | **R‑** | Installation depuis un dépôt relais interne de l'entité | Aligné sur R43 ; suppose un dépôt maîtrisé. |

### 5.8 Marquage

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| MARQ-1 | **R** | Marquage automatique du niveau de sensibilité en tête de chaque contenu restitué, libellé fixé par l'instance | Répond à l'exigence de marquage des informations sensibles ; ne dépend pas de la discipline de l'émetteur. |
| MARQ-2 | **R‑‑** | Aucun marquage | Zones sans exigence de marquage. |

### 5.9 Rémanence côté client

Le client peut conserver localement le contenu chiffré tel qu'il l'a reçu, indexé par l'empreinte de l'identifiant serveur. La clé demeurant dans l'identifiant détenu par l'utilisateur, le cache n'introduit aucun secret nouveau au repos : il offre le même niveau de protection que le serveur, sans le serveur. Cette rémanence permet d'imposer la destruction serveur dès la première lecture tout en autorisant l'utilisateur à rejouer sa commande (ADR-013).

L'autorisation du cache est déclarée par le serveur, non choisie par le destinataire : sans cela, l'émetteur perdrait la maîtrise de la durée de vie de ce qu'il a transmis.

| ID | Niveau | Option | Conditions d'emploi |
|---|---|---|---|
| CACHE-1 | **R** | Aucune rémanence : le contenu n'existe côté client que le temps de sa restitution | Option nominale. La durée de vie déclarée par l'émetteur est respectée de bout en bout. |
| CACHE-2 | **R‑** | Cache local du contenu chiffré, sur support chiffré du poste, purgé à l'échéance de l'ardoise et jamais au-delà | Permet la destruction serveur immédiate. Suppose un poste conforme à R14. Le contenu survit sur le poste jusqu'à l'échéance, hors de tout contrôle serveur. |
| CACHE-3 | **R‑‑** | Cache local sans échéance propre, purgé sur demande de l'utilisateur | Aucune garantie de disparition. Hors contexte réglementé uniquement. |

## 6. Configurations exigées en contexte réglementé

Les options ci-dessous constituent des **minima** : une entité peut toujours retenir une option de niveau supérieur, jamais inférieur. Elles sont livrées sous forme de configurations de référence signées, accompagnées des éléments de dossier correspondants.

### 6.1 Systèmes relevant de l'II 901 (Diffusion Restreinte)

| Dimension | Minimum exigé | Justification |
|---|---|---|
| Identification | AUTH-3 (**R‑**) | L'accès à des informations DR doit être rattaché à une personne identifiée. L'identification déclarative (AUTH-4) ne permet ni le contrôle du besoin d'en connaître, ni l'investigation en cas d'incident. AUTH-2 recommandé dès lors qu'une IGC existe (R37). |
| Durée de vie | TTL-2 (**R**) | R57 fixe le délai raisonnable de suppression à l'ordre de 24 h ; au-delà, le service cesse d'être un système d'échange et devient un stockage, non couvert par l'homologation du composant. |
| Conservation | RET-2 (**R**) | L'absence de persistance sur support réduit la surface de compromission et évite qu'un support contenant des informations DR ne relève des procédures de traitement et de destruction associées. RET-3 admissible si le support est chiffré et intégré au périmètre homologué. |
| Protection des contenus | CHIF-2 (**R**) en mode aveugle ; CHIF-4 (**R‑‑**) en mode analysé | En mode aveugle, le chiffrement de bout en bout garantit qu'aucune information DR n'est lisible sur le serveur. En mode analysé, l'accès transitoire au clair est la contrepartie assumée de R58 ; il est borné et documenté (annexe A.3). |
| Analyse de contenu | ANA-2 (**R**) en mode analysé ; ANA-3 (**R‑**) en mode aveugle | R58 impose l'analyse systématique sur le système d'échange externe. En mode aveugle, R58 est sans objet, mais la détection de secrets reste requise pour éviter le dépôt d'authentifiants dans un service non prévu à cet effet (R35). |
| Journalisation | JOURN-2 (**R**) | R46 et R47 imposent une zone de journalisation dédiée et une collecte centralisée. JOURN-3 place le journal sous le contrôle de l'administrateur de l'instance, ce qui prive l'entité d'un élément de preuve indépendant. |
| Transport | TLS-2 (**R**) | R24 impose des protocoles de chiffrement et d'authentification robustes. TLS-1 exigé si les flux traversent un réseau non maîtrisé (R21). |
| Marquage | MARQ-1 (**R**) | Le marquage des informations DR est une obligation de porteur ; l'automatiser au niveau de l'instance évite qu'il dépende de la vigilance de l'émetteur. |
| Rémanence côté client | CACHE-1 (**R**) ; CACHE-2 (**R‑**) admissible | La rémanence n'est acceptable que si le poste chiffre ses supports (R14), si la purge intervient au plus tard à l'échéance, et si le cache est intégré au périmètre homologué. CACHE-3 est exclue : une information DR sans échéance de destruction n'est plus dans un système d'échange. |
| Distribution | DIST-1 ou DIST-2 (**R**/**R‑**) | R13 impose un processus de validation et de distribution maîtrisé des outils d'administration. |

### 6.2 Systèmes classifiés relevant de l'IGI 1300

Aux minima du §6.1 se substituent ou s'ajoutent :

| Dimension | Minimum exigé | Justification |
|---|---|---|
| Identification | AUTH-2 (**R**) | L'imputabilité des actions sur des informations classifiées suppose une identité authentifiée par un mécanisme robuste ; un jeton d'annuaire (AUTH-3) est admis uniquement à titre transitoire et documenté. AUTH-1 recommandé. |
| Journalisation | JOURN-2 (**R**), JOURN-1 (**R+**) recommandé | L'imputabilité est une exigence structurante du régime de protection du secret. Le chaînage des entrées (JOURN-1) protège la chaîne de preuve contre l'altération par un administrateur. Aucune option JOURN-3 ou JOURN-4 n'est admissible. |
| Conservation | RET-2 (**R**) | L'absence de persistance évite la création de supports classifiés non identifiés, qui relèveraient sinon des règles d'inventaire, de conservation et de destruction applicables. |
| Durée de vie | TTL-2 (**R**), TTL-1 (**R+**) recommandé | Le principe du besoin d'en connaître implique qu'une information partagée pour une tâche ne survive pas à cette tâche. |
| Distribution | DIST-1 (**R**) | Les SI classifiés étant isolés (§13.5), l'installation et les mises à jour doivent être intégralement réalisables hors ligne, à partir de paquets signés vérifiables localement. DIST-2 est inapplicable. |
| Mode | Mode aveugle exclusivement | Le mode analysé suppose une interconnexion avec un SI de moindre sensibilité. Une passerelle vers un SI classifié relève de produits agréés et d'une homologation spécifique, hors périmètre du produit (§13.5). |
| Rémanence côté client | CACHE-1 (**R**) | Un cache créé par l'outil constituerait un support classifié non identifié, échappant aux règles d'inventaire, de conservation et de destruction. Aucune option de rémanence n'est admissible. |
| Marquage | MARQ-1 (**R**) | Le marquage des supports et des informations classifiées est une obligation permanente. |

### 6.3 Instances en mode analysé (système d'échange externe)

Indépendamment du niveau de sensibilité, les recommandations R54 à R58 s'appliquent à toute instance en mode analysé :

| Dimension | Minimum exigé | Justification |
|---|---|---|
| Source des identités | Distincte du SI d'administration, quel que soit le mécanisme retenu | R56 interdit l'authentification par un compte d'administration sur un système d'échange externe, considéré de moindre confiance. |
| Analyse de contenu | ANA-2 (**R**) | R58 impose l'analyse systématique des données transitant par le système d'échange. Le refus de dépôt en l'absence de verdict est la seule traduction fidèle de « systématiquement ». |
| Durée de vie | TTL-2 (**R**) | Application directe de R57. |
| Opérations exposées | Transfert uniquement | Application de R54 ; garantie par construction (ADR-007). |
| Accès | Restreint aux postes et utilisateurs ayant le besoin de transférer | Application de R55, mise en œuvre par le filtrage et le contrôle d'accès de l'entité (HE-4). |

## 7. Matrice de couverture ANSSI-PA-022

Trois modes de couverture : **C** — satisfait par construction (aucune configuration ne peut le défaire) ; **P** — satisfait par la configuration d'instance (option retenue, cf. §5 et §6) ; **E** — hypothèse d'environnement, à la charge de l'entité (§3.3).

| Rec. | Objet | Mode | Réponse ardoise |
|---|---|---|---|
| R10 | Pas d'Internet sur poste d'administration | C | Aucune fonction du produit ne requiert d'accès Internet ; le besoin d'échange de texte est satisfait dans le périmètre. |
| R13 | Outils validés et distribués par processus | E/P | Binaire signé, empreintes publiées, builds reproductibles (DIST-1/DIST-2) ; distribution via la télédistribution de l'entité (HE-3). |
| R15/R16 | Réseau d'administration dédié, filtrage | E | Un seul port exposé ; matrice de flux à une ligne (HE-1). |
| R21 | Flux traversant un réseau tiers | P | TLS-1 : encapsulation IPsec des flux hors périmètre maîtrisé. |
| R22 | Outils déployés par zone d'administration | C | Une instance par zone ; aucune liaison inter-instances (ES-6). |
| R24 | Protocoles sécurisés pour les flux | P | TLS obligatoire ; niveau selon TLS-1/2/3 (§5.7). |
| R31/R46/R47 | Journalisation, zone dédiée, collecte centralisée | P | JOURN-1/2 : émission des métadonnées vers le collecteur central ; aucune archive locale. |
| R35 | Coffre-fort de mots de passe | C | Le produit n'est pas un coffre-fort et alerte lorsqu'un secret est détecté (ES-12, ADR-007). |
| R36/R37 | Authentification double facteur, certificats de confiance | P | AUTH-1/2 (§5.2) ; minima imposés en contexte réglementé (§6). |
| R42/R43 | MCS, dépôts relais | E/P | Paquets signés installables hors ligne ; compatibilité dépôts relais internes (DIST-1/2). |
| R52 | Déployer des systèmes d'échanges sécurisés | C | Ardoise est une implémentation de ce composant. |
| R53 | Système d'échange interne dédié, sans interconnexion | C/E | Mode aveugle : infrastructure d'administration sans interconnexion (§4.5, HE-1). |
| R54 | Transfert uniquement, aucune session de travail | C | Deux opérations exposées ; pas de shell, pas de session, pas d'exécution. |
| R55 | Accès au strict besoin opérationnel | E/P | Filtrage et contrôle d'accès de l'entité (HE-4) ; authentification selon l'option retenue. |
| R56 | Pas de compte d'administration sur le système d'échange externe | P | Mode analysé : source d'identités distincte du SI d'administration (§6.3). |
| R57 | Pas de stockage permanent ; suppression ≤ 24 h | C/P | Durée de vie obligatoire par construction (ADR-003) ; borne selon TTL-1/2/3. |
| R58 | Analyse de contenu sur le système d'échange externe | P | ANA-1/2 : soumission ICAP synchrone bloquante (ADR-004, ADR-011). |

## 8. Exploitation

- **Supervision** : l'instance expose son état de fonctionnement, sans information sur les contenus ; les événements de sécurité partent vers la zone de journalisation lorsque celle-ci est configurée.
- **Maintien en condition de sécurité** : versions signées, procédure de mise à jour hors ligne documentée, suivi des vulnérabilités publié.
- **Sauvegarde** : sans objet pour les contenus (éphémères par exigence ES-1) ; seule la configuration d'instance est à sauvegarder.
- **Réversibilité** : la suppression d'une instance n'entraîne aucune perte de donnée métier, par construction.

## 9. Décisions d'architecture (ADR)

### ADR-001 — Binaire unique client + serveur
**Statut : accepté.**
**Contexte.** L'outil doit être auditable, distribuable par télédistribution (R13), transférable en environnement isolé (§13.5), et homologable à coût minimal.
**Décision.** Un seul binaire Go statique porte les rôles client et serveur (`serve`, `push`, `get`). Aucune dépendance à l'exécution, builds reproductibles.
**Conséquences.** Un seul artefact à auditer, signer, valider et transférer. Surface d'homologation minimale. En contrepartie, client et serveur partagent un cycle de version.

### ADR-002 — La configuration de sécurité est une propriété de l'instance
**Statut : accepté.**
**Contexte.** Une sécurité reposant sur des options choisies par l'utilisateur au moment de l'envoi dépend de sa discipline ; les exigences varient selon le mode, la sensibilité de la zone et les moyens de l'entité.
**Décision.** Toutes les options du §5 sont déclarées dans la configuration serveur, appliquées par le serveur, et opposables au client. Le client interroge la configuration, l'affiche avant envoi, et ne dispose d'aucun moyen de l'affaiblir.
**Conséquences.** La conformité d'un déploiement se lit dans un unique fichier signé, versable au dossier d'homologation. Le client doit prendre en charge l'ensemble des options.

### ADR-003 — Éphémérité structurelle
**Statut : accepté.**
**Contexte.** R57 interdit le stockage permanent sur un système d'échange ; l'accumulation de contenus crée un actif attaquable.
**Décision.** Toute ardoise porte une durée de vie. Les bornes sont configurables (§5.3) ; l'absence de durée de vie ne l'est pas. Aucune option de conservation illimitée n'existe dans le produit.
**Conséquences.** Le produit ne peut pas servir d'archive ni de référentiel documentaire — non-objectif assumé (ADR-007).

### ADR-004 — Détection de secrets côté client ; analyse de contenu côté serveur en mode analysé
**Statut : accepté.**
**Contexte.** Le chiffrement de bout en bout est l'objectif nominal du produit, mais R58 exige une analyse systématique des contenus transitant par le système d'échange externe. Un serveur aveugle ne peut pas analyser ce qu'il ne peut pas lire.
**Décision.** Mode **aveugle** : chiffrement de bout en bout, R58 sans objet, détection de secrets côté client avant chiffrement. Mode **analysé** : la détection de secrets reste côté client ; l'analyse de contenu s'exécute côté serveur, de manière **synchrone et bloquante** — le contenu n'est mis à disposition qu'après verdict favorable, et le dépôt est refusé en l'absence de verdict (*fail-closed*). Après verdict, le serveur chiffre le contenu avec une clé remise à l'émetteur puis effacée (cécité a posteriori) ; le contenu n'est jamais écrit en clair.
**Conséquences.** En mode analysé, le serveur accède transitoirement au contenu en clair : le chiffrement de bout en bout est une propriété du mode aveugle uniquement, et le client l'affiche explicitement à l'utilisateur avant tout envoi. La conformité R58 est systématique par construction.

### ADR-005 — Journaliser les actes, jamais les contenus
**Statut : accepté.**
**Contexte.** L'IGI 1300 et la supervision de sécurité (R31, R46, R47) exigent l'imputabilité ; l'éphémérité et le chiffrement interdisent la rétention des contenus.
**Décision.** La journalisation, selon l'option retenue (§5.6), porte exclusivement sur les métadonnées : identité de l'émetteur et **mécanisme d'identification employé** (authentifié ou déclaratif), horodatages de création, de lecture et de destruction, empreinte du contenu chiffré, instance et niveau. Aucun contenu, aucune clé, aucun identifiant complet.
**Conséquences.** La force de l'imputabilité est lisible dans le journal lui-même : une entrée produite sous identification déclarative (AUTH-4) est explicitement marquée comme telle et ne peut être présentée comme une preuve d'imputation.

### ADR-006 — Une instance par zone, aucune liaison inter-instances
**Statut : accepté.**
**Contexte.** R22 impose le déploiement des outils par zone d'administration ; le §13.2 interdit toute mutualisation entre SI de classifications différentes et encadre strictement les autres.
**Décision.** Une instance dessert une zone. Le produit ne comporte aucune fonction de fédération, de réplication ou de liaison entre instances.
**Conséquences.** Aucune passerelle inter-zones ne peut être créée par l'outil, même par erreur de configuration. Chaque dossier d'homologation reste local à sa zone.

### ADR-007 — Surface fonctionnelle minimale (non-objectifs)
**Statut : accepté.**
**Contexte.** Chaque fonction ajoute une surface d'attaque et une charge d'évaluation ; certaines contrediraient les exigences (ES-1, R54).
**Décision.** Sont exclus : le listage des ardoises existantes, l'édition, les comptes utilisateurs côté serveur, la recherche, le dépôt de fichiers arbitraires, toute fonction de coffre-fort de secrets. La détection de secrets (ES-12) alerte l'utilisateur que ce type de contenu relève d'un coffre-fort dédié (R35).
**Conséquences.** Le produit reste lisible intégralement par un auditeur en temps contraint. Les besoins exclus sont adressés par d'autres composants du SI (R35, R52).

### ADR-008 — Distribution signée, fonctionnement hors ligne natif
**Statut : accepté.**
**Contexte.** R13, R42/R43 et §13.5 ; les SI classifiés sont physiquement isolés.
**Décision.** Paquets signés, empreintes publiées, builds reproductibles, installation intégralement hors ligne possible, aucune vérification en ligne (licence, télémétrie, mise à jour automatique). Le fonctionnement hors ligne est nominal, pas dégradé.
**Conséquences.** Compatible dépôts relais et procédures de transfert maîtrisé. La vérification des signatures et l'import relèvent des processus de l'entité (HE-3).

### ADR-009 — Identification exigée par le serveur, mécanisme gradué
**Statut : accepté.**
**Contexte.** L'imputabilité suppose une identité authentifiée, mais les moyens disponibles dépendent de l'entité : le guide recommande le double facteur (R36) et les certificats (R37) sans les imposer, et toutes les organisations ne disposent pas d'une IGC déployée jusqu'aux postes d'administration. Un produit exigeant un mécanisme unique serait non déployable dans une partie des environnements visés.
**Décision.** Le serveur exige systématiquement que chaque opération soit rattachée à une identité ; aucune configuration n'autorise le dépôt ou la récupération anonymes. Le mécanisme est choisi par l'instance parmi les options graduées du §5.2, de AUTH-1 (**R+**) à AUTH-4 (**R‑‑**, déclaratif). Les minima applicables en contexte réglementé sont fixés au §6. En mode analysé, quel que soit le mécanisme, les identités et secrets employés ne proviennent jamais du SI d'administration (R56).
**Conséquences.** Le produit s'adapte au niveau de maturité de l'entité sans jamais autoriser l'anonymat. La valeur probante de la journalisation varie avec le mécanisme retenu, ce que les métadonnées consignent explicitement (ADR-005).

### ADR-010 — Deux modes, options graduées selon la convention du guide
**Statut : accepté.**
**Contexte.** Les déploiements se répartissent selon deux positions au sens du guide et desservent des zones de sensibilités variées, dans des entités aux moyens inégaux. Une déclinaison en configurations figées par couple position × sensibilité serait redondante, coûteuse à maintenir et inadaptée à la diversité réelle des environnements ; à l'inverse, une configurabilité libre rendrait tout déploiement inévaluable.
**Décision.** Le produit expose deux modes structurels (§4.5), et à l'intérieur de chacun, un ensemble fermé d'options graduées selon la convention R / R‑ / R‑‑ / R+ du guide (§5). Le produit n'impose pas de niveau par lui-même ; les minima réglementaires sont énoncés au §6 et livrés sous forme de configurations de référence signées.
**Conséquences.** Le choix d'un déploiement s'exprime dans le vocabulaire du référentiel qui l'encadre, ce qui rend l'écart de conformité immédiatement lisible par une autorité d'homologation. L'ensemble des options étant fermé et énuméré, l'espace des configurations reste évaluable.

### ADR-011 — Intégration de l'analyse de contenu par ICAP
**Statut : accepté.**
**Contexte.** R58 impose l'analyse des contenus en mode analysé. Les entités disposent déjà de moteurs d'analyse ; les solutions du marché exposent une interface ICAP (RFC 3507). Le produit ne doit ni embarquer un moteur, ni imposer un fournisseur.
**Décision.** Le serveur implémente un client ICAP. En mode analysé, chaque contenu déposé est soumis à l'adresse ICAP déclarée ; le verdict conditionne la mise à disposition (ADR-004). Les moteurs — antivirus, détection de code malveillant, règles propres à l'entité — sont fournis, hébergés et administrés par l'entité. Le délai d'attente est configurable ; le comportement en cas d'indisponibilité ou de dépassement est le refus de dépôt (*fail-closed*), non désactivable.
**Conséquences.** Interopérabilité avec les chaînes d'analyse existantes, sans dépendance produit. Le périmètre de responsabilité est net : ardoise garantit le caractère systématique et bloquant de la soumission (R58) ; la pertinence des verdicts relève de la chaîne d'analyse de l'entité et n'est pas une promesse du produit.

### ADR-012 — Licence : Apache 2.0 assortie de la Commons Clause
**Statut : accepté, sous réserve de validation juridique.**
**Contexte.** Objectifs : code source public, lisible et auditable ; usage, déploiement et modification gratuits pour tous ; interdiction unique — la vente du logiciel ou de services dont la valeur en provient substantiellement — opposable à tous, éditeur inclus. Les licences libres au sens OSI (AGPL, GPL, Apache seule, EUPL, CeCILL) autorisent l'exploitation commerciale. Les licences purement non commerciales (PolyForm Noncommercial, Prosperity) interdisent aussi l'usage interne par une entité à but lucratif, ce qui contredit la gratuité universelle visée.
**Décision.** Apache 2.0 complétée par la Commons Clause : toutes les libertés d'Apache sont conservées à l'exception du droit de vendre. Le projet se présente comme « source disponible » et ne revendique pas le label « open source ». Les contributions externes sont soumises à un accord de contribution préservant la capacité de gestion de licence du projet.


### ADR-013 — Rémanence client optionnelle, autorisée par le serveur
**Statut : accepté.**
**Contexte.** La destruction à la première lecture est la traduction la plus fidèle de R57, mais elle pénalise l'usage courant : une commande rejouée, un tube interrompu, un terminal fermé, et le contenu est perdu. Le compromis habituel consiste à allonger la durée de vie serveur, ce qui dégrade la propriété que l'on cherchait à renforcer.
**Décision.** Le client peut, lorsque l'instance l'autorise, conserver localement le **contenu chiffré tel que reçu**, indexé par l'empreinte de l'identifiant serveur ; la clé reste dans l'identifiant détenu par l'utilisateur et n'est jamais écrite. L'échéance du cache ne peut excéder celle de l'ardoise. L'autorisation et le niveau (§5.9) sont déclarés par le serveur ; le client ne peut pas les outrepasser.
**Conséquences.** La destruction côté serveur peut intervenir dès la première lecture sans perte d'ergonomie. En contrepartie, le contenu survit sur le poste destinataire jusqu'à l'échéance : la garantie de disparition devient conditionnée au respect de l'échéance par le poste, lui-même supposé géré et durci (HE-2). Le cache n'introduit aucun secret nouveau au repos, la clé n'y figurant pas.

## 10. Points ouverts

| ID | Point | Statut |
|---|---|---|
| PO-1 | Typologie des configurations. | **Clos** — ADR-010 : deux modes, options graduées (§5), minima réglementaires (§6). |
| PO-2 | Régime d'analyse R58 en mode analysé. | **Clos** — ADR-004 et ADR-011. |
| PO-3 | Choix de la licence. | **Clos**, sous réserve de validation juridique — ADR-012. |
| PO-4 | Trajectoire d'évaluation externe. | **Retiré** — hors périmètre du présent document. |
| PO-5 | Modèle de menace et inventaire cryptographique. | **Clos** — annexes A et B. |
| PO-6 | Lecture par un groupe. | **Retiré** — hors périmètre. |

## Annexe A — Modèle de menace (synthèse)

### A.1 Biens à protéger

| Bien | Besoins |
|---|---|
| Contenu des ardoises | Confidentialité, intégrité |
| Matériel de clé | Confidentialité |
| Métadonnées d'imputabilité | Intégrité, disponibilité de l'acheminement vers la zone de journalisation |
| Disponibilité du service | Faible criticité : contenus éphémères, recouvrables par réémission |

### A.2 Attaquants considérés et parades

| ID | Attaquant | Parade principale |
|---|---|---|
| A1 | Attaquant réseau au sein de la zone | TLS (§5.7) ; filtrage d'environnement (HE-1, HE-4) ; identification exigée (§5.2) |
| A2 | Compromission du serveur ardoise | Mode aveugle : le serveur ne détient que du chiffré et des métadonnées ; les clés n'y ont jamais existé. Mode analysé : exposition limitée aux contenus présents pendant la fenêtre d'analyse (A.3) |
| A3 | Administrateur malveillant de l'instance | Mêmes propriétés que A2 ; journalisation vers une zone qu'il n'administre pas (JOURN-1/2, R46) — parade inopérante avec JOURN-3 ou JOURN-4 |
| A4 | Saisie physique ou réquisition du serveur | Mode aveugle : rien d'exploitable hors chiffré et métadonnées ; après expiration, rien du tout (ES-1). RET-3 étend transitoirement l'exposition au support |
| A5 | Tiers obtenant un identifiant complet | Le porteur de l'identifiant détient la clé ; la protection de l'identifiant incombe à l'émetteur (canal hors périmètre). Durée de vie courte, destruction à première lecture et TTL contraignant réduisent la fenêtre |
| A6 | Poste client compromis | Hors périmètre produit : hypothèse HE-2 (poste d'administration durci, chapitre 4 du guide) |
| A7 | Usurpation d'identité d'un émetteur | Neutralisée par AUTH-1/2, atténuée par AUTH-3 ; **non couverte** par AUTH-4, où seule la maîtrise de l'accès réseau fait obstacle |
| A8 | Exploitation des journaux | Les journaux ne contiennent ni contenu, ni clé, ni identifiant complet |
| A9 | Accès au cache d'un poste destinataire | Le cache ne contient que du chiffré, sans clé : inexploitable sans l'identifiant correspondant (§5.9). Purge à l'échéance ; chiffrement du support (R14, HE-2) |

### A.3 Risques résiduels acceptés

1. **Fenêtre en clair du mode analysé** : pendant l'analyse, le contenu est en clair en mémoire serveur ; une compromission du serveur durant cette fenêtre expose les contenus en transit. Atténuation : durée bornée par le délai ICAP, aucune écriture en clair, serveur durci (HE-1, corpus PA-022 applicable au serveur en tant que ressource d'administration).
2. **Effacement mémoire en Go** : le ramasse-miettes ne garantit pas l'absence de copies résiduelles du matériel de clé malgré l'effacement explicite. Atténuation : manipulation en tampons dédiés, effacement systématique, hypothèses HE-1/HE-2.
3. **Transmission de l'identifiant** : le canal par lequel l'émetteur transmet l'identifiant au destinataire est hors périmètre ; un identifiant intercepté équivaut à la connaissance du contenu jusqu'à expiration.
4. **Rémanence côté client (CACHE-2, CACHE-3)** : le contenu survit sur le poste destinataire après sa destruction sur le serveur. La garantie de disparition repose alors sur le respect de l'échéance par le poste et sur son durcissement (HE-2). Le cache ne contient que du chiffré, la clé restant dans l'identifiant détenu par l'utilisateur.
5. **Identification déclarative (AUTH-4)** : l'identité consignée n'est pas vérifiée et peut être falsifiée par tout client autorisé à joindre l'instance. Acceptée uniquement hors contexte réglementé, sur réseau d'administration cloisonné ; les journaux la marquent comme déclarative.

## Annexe B — Inventaire cryptographique

| Fonction | Choix | Paramètres et justification |
|---|---|---|
| Chiffrement authentifié | AES-256-GCM | Clé 256 bits **à usage unique par ardoise** (jamais deux messages sous une même clé, neutralisant le risque de réutilisation de nonce) ; nonce 96 bits aléatoire. Alignement RGS annexe B1. |
| Génération d'aléa | `crypto/rand` exclusivement | Clés, nonces, sels, identifiants. |
| Dérivation de clé (mot de passe) | Argon2id | Mémoire 64 Mio, itérations 3, parallélisme 4 ; sel 128 bits aléatoire, stocké avec l'objet chiffré (non secret). |
| Format d'identifiant | `<id-serveur>#<clé en base64url>` | Le séparateur `#` garantit qu'en contexte d'URL le matériel de clé reste dans le fragment, jamais transmis au serveur. |
| Intégrité | Tag GCM + empreinte SHA-256 du chiffré | Empreinte retournée au dépôt, vérifiée à la lecture ; alimente les métadonnées d'imputabilité (ADR-005). |
| Transport | TLS 1.3 (1.2 en option dégradée TLS-3) | Suites conformes au guide TLS de l'ANSSI ; autorité de certification interne, épinglage ; mTLS selon AUTH-1/2. |
| Mode analysé (cécité a posteriori) | Clé générée par le serveur après verdict ICAP | Retournée à l'émetteur dans la réponse de dépôt, puis effacée ; présente en mémoire uniquement pendant la fenêtre d'analyse (ADR-004). |
| Journaux chaînés (JOURN-1) | Chaînage par empreinte SHA-256 de l'entrée précédente | Détection d'altération ou de suppression d'entrée. |
| Hygiène mémoire | Effacement explicite, best effort | Matériel de clé en `[]byte`, jamais converti en chaîne ; aucun contenu, clé ou identifiant complet dans les journaux et messages d'erreur ; limite du ramasse-miettes documentée (A.3-2). |
| Comparaisons | Temps constant | Pour tout jeton ou secret comparé côté serveur. |
| Compression | Aucune avant chiffrement (v1) | Évite toute classe d'oracle liée à la compression. |
| Conformité visée | Référentiel cryptographique ANSSI (RGS annexe B1) | Mécanismes, tailles de clés, générateurs. |
