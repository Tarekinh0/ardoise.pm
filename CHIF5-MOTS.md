# CHIF-5 — Récupération par 5 mots mnémoniques

**Statut** : implémenté, testé — intégré en V1  
**Date** : 2026-07-25  
**Produit** : ardoise.pm  
**ADR de référence** : docs/dat.md §5.4, annexe B  
**Version cible** : V1  
**Niveau** : R−, hors contexte réglementé  

---

## 1. Rappel du problème et décision architecturale

### 1.1 Problème initial

L'identifiant Ardoise actuel est une chaîne opaque de ~55 caractères :
```
a7f3k9x2#Zt8mQ4vP1nKcW7yE0sJdL5hB2gT6uX
```
Peu lisible, difficile à dicter au téléphone, impossible à mémoriser. L'utilisateur souhaite une représentation en **quelques mots** — idéalement 5 — pour « simplifier la gestion du partage de secrets ».

### 1.2 Pourquoi pas 24 mots BIP39 ?

Une analyse initiale proposait 24 mots BIP39 encodant directement une clé AES-256. Rejetée par l'utilisateur : « 24 mots pour partager un script de 3 lignes c'est incohérent. » Le ratio ergonomique est défavorable au cas d'usage principal du pastebin (petits fragments texte, durée de vie ≤ 7 jours).

### 1.3 Décision : 5 mots BIP39 + Argon2id

| Paramètre | Valeur |
|---|---|
| Nombre de mots | **5** |
| Liste | BIP39 français (2048 mots, 11 bits/mot) |
| Entropie de la passphrase | **55 bits** (5 × 11) |
| Fonction d'étirement | Argon2id (64 Mio, 3 itérations, parallélisme 4) → graine 256 bits |
| Dérivation ID serveur | HKDF-SHA256(graine, sel="", info="ardoise.pm/mots/id/v1") → 12 caractères `[a-z2-9]` |
| Dérivation clé AES-256 | HKDF-SHA256(graine, sel=blob_salt, info="ardoise.pm/mots/chiffre/v1") → 32 octets |
| Format chiffré | Version `0x06` : `0x06 ‖ blob_salt(16) ‖ nonce(12) ‖ scellé` |
| Coût au get | ~0,5 seconde (un seul appel Argon2id) |
| Nouvel octet de version | `0x06` |
| Compatibilité | Coexiste avec CHIF-2 (cle), CHIF-4 (serveur), CHIF-MD (multi-dest.) |

### 1.4 Compromis de sécurité assumé

| Propriété | CHIF-2 actuel (clé aléatoire) | CHIF-5 (5 mots) | Accepté ? |
|---|---|---|---|
| Entropie brute | 256 bits | 55 bits étirés à 256 par Argon2id | ✅ Oui — TTL ≤ 7 jours |
| Indépendance ID/clé | Totale (deux aléas crypto/rand) | Liés (ID dérivé de la graine Argon2id) | ✅ Oui — la préimage Argon2id est infaisable |
| Résistance post-quantique | AES-256 → 128 bits avec Grover | AES-256 mais passphrase 55 bits → ~27,5 bits effectifs quantiques | ✅ Oui — le produit complet n'est pas post-quantique |
| Brute-force 100K machines | Infaisable (2^256) | ~2,8 ans pour l'espace entier (espérance 1,4 an) | ✅ Oui — fenêtre TTL 7 jours << 1,4 an |
| Partage sans état | Client seulement (id#cle suffit) | Client seulement (5 mots suffisent) | ✅ Oui — identique |

**Rationnel** : pour la durée de vie maximale d'une ardoise (7 jours, ADR-003), un acteur disposant de 100 000 machines spécialisées Argon2id ne couvre que ~0,7% de l'espace des passphrases. Le risque résiduel est acceptable pour le niveau de sensibilité cible. Pour des contenus de sensibilité supérieure, l'utilisateur reste libre d'utiliser le mode `id#cle` standard (256 bits).

---

## 2. Schéma cryptographique complet

### 2.1 Génération des 5 mots

```
Entrée  : crypto/rand (55 bits = 5 × 11 bits)
Sortie  : 5 mots français BIP39

Algorithme :
  1. tirer 7 octets (56 bits) via crypto/rand
  2. ne conserver que les 55 bits de poids faible
  3. découper en 5 groupes de 11 bits
  4. chaque groupe (0–2047) indexe la liste BIP39 française
  5. retourner les 5 mots séparés par des tirets
```

**Note** : Pas de checksum BIP39 (trop coûteux : 8 bits de checksum sur 55 bits = perte d'entropie ou mot supplémentaire). La validation se fait par l'absence de l'ardoise (code 5) en cas d'erreur de saisie.

### 2.2 Argon2id : de la passphrase à la graine

```
Fonction : DeriverGraine(mots []string) []byte

Paramètres (conformes à l'annexe B du DAT) :
  - password   = concaténation des 5 mots avec tirets : "chat-lune-arbre-soleil-porte"
  - salt       = chaîne fixe "ardoise.pm/mots/v1" (encodée UTF-8, 21 octets)
  - time       = 3 (itérations)
  - memory     = 64 × 1024 Kio (64 Mio)
  - threads    = 4 (parallélisme)
  - keyLen     = 32 (256 bits)

Sortie : graine de 32 octets (256 bits pseudo-aléatoires)

Justification du sel fixe :
  - Le sel Argon2id ne nécessite PAS d'être secret (c'est documenté)
  - Un sel fixe permet de retrouver la même graine depuis les mêmes mots,
    sans stocker de sel par blob
  - La diversification par blob se fait EN AVAL via HKDF avec blob_salt
  - Avantage décisif : Argon2id est appelé UNE SEULE FOIS au get, 
    et HKDF (microsecondes) diversifie par blob
```

### 2.3 Dérivation de l'ID serveur

```
Fonction : DeriverIDDepuisGraine(graine []byte) (string, error)

  1. idSeed = HKDF-SHA256(
       ikm  = graine,
       salt = nil,
       info = "ardoise.pm/mots/id/v1",
       len  = 32
     )
  2. Encoder idSeed en 12 caractères de l'alphabet [a-z2-9] (34 symboles)
     via l'algorithme d'échantillonnage avec rejet (identique à NouvelIDServeur
     mais alimenté par un PRNG déterministe — HMAC-DRBG — initialisé avec idSeed)
  3. Retourner l'ID (12 caractères)

Propriété de sécurité :
  - HKDF est une PRF : idSeed est calculatoirement indépendant de la clé
  - La projection vers 12 caractères (~61 bits) crée une fonction à sens unique
    depuis la graine (256 bits). Connaître l'ID ne donne pas la graine.
```

### 2.4 Dérivation de la clé AES-256

```
Fonction : DeriverCleDepuisGraine(graine, blobSalt []byte) ([]byte, error)

  1. cle = HKDF-SHA256(
       ikm  = graine,
       salt = blobSalt,
       info = "ardoise.pm/mots/chiffre/v1",
       len  = 32
     )
  2. Retourner cle (32 octets = AES-256)

Où blobSalt provient de crypto/rand (16 octets) lors du push,
et est extrait de l'en-tête du chiffré lors du get.

Justification du blob_salt :
  - blob_salt est stocké DANS le chiffré (non secret)
  - Il garantit que deux ardoises créées avec les MÊMES mots 
    produisent des clés AES DIFFÉRENTES
  - Il n'est PAS un sel Argon2id (ne nécessite pas de recalcul coûteux)
  - HKDF avec sel blob_salt coûte ~microsecondes
```

### 2.5 Format du chiffré (version 0x06)

```
Octet 0       : 0x06 (VersionMots, nouveau schéma CHIF-5)
Octets 1–16   : blob_salt (16 octets, sel HKDF)
Octets 17–28  : nonce (12 octets, GCM, crypto/rand)
Octets 29–fin : scellé AES-256-GCM (clair + tag 16 octets)

Taille minimale : 1 + 16 + 12 + 16 = 45 octets

┌────────┬──────────────────┬──────────────┬──────────────────────────┐
│ 0x06   │ blob_salt (16)   │ nonce (12)   │ scellé GCM (clair+tag)   │
│ 1 octet│ 16 octets        │ 12 octets    │ variable (≥16 octets)    │
└────────┴──────────────────┴──────────────┴──────────────────────────┘
           ←─────── AAD (17 octets) ───────→
```

L'en-tête complet (version ‖ blob_salt) est passé en **données additionnelles authentifiées (AAD)** du GCM : toute altération de l'en-tête fait échouer le déchiffrement.

### 2.6 Pourquoi Argon2id une seule fois ?

```
┌─── Push ───────────────────────────┐  ┌─── Get ───────────────────────────┐
│                                    │  │                                    │
│ Argon2id(mots, sel_fixe) → graine  │  │ Argon2id(mots, sel_fixe) → graine  │
│         (~0,5s)                    │  │         (~0,5s)                    │
│         │                          │  │         │                          │
│         ├─→ HKDF(graine)→ ID       │  │         ├─→ HKDF(graine)→ ID       │
│         │   (microsecondes)        │  │         │   (microsecondes)        │
│         │                          │  │         │                          │
│         └─→ blob_salt = rand(16)   │  │         └─→ blob_salt ← extrait    │
│             HKDF(graine, blob_salt)│  │             du chiffré             │
│             → cle (microsecondes)  │  │             HKDF(graine, blob_salt)│
│                                    │  │             → cle (microsecondes)  │
│  Coût total : ~0,5s                │  │  Coût total : ~0,5s                │
└────────────────────────────────────┘  └────────────────────────────────────┘
```

**Alternative rejetée** : Utiliser `blob_salt` comme sel Argon2id → un Argon2id par blob → 0,5s **supplémentaires** au déchiffrement. La séparation sel_fixe (Argon2id) / blob_salt (HKDF) est le **point architectural clé** qui rend le get acceptable (~0,5s au lieu de ~1s).

---

## 3. Flux complets

### 3.1 Push aveugle avec `--mots`

```
┌─ Client ─────────────────────────────────────────────────┐  ┌─ Serveur ──────┐
│                                                           │  │                │
│ 1. Lire contenu (stdin ou fichier)                        │  │                │
│                                                           │  │                │
│ 2. mots = crypto.GenererMots(5)                           │  │                │
│    → ["chat", "lune", "arbre", "soleil", "porte"]         │  │                │
│                                                           │  │                │
│ 3. graine = crypto.DeriverGraine(mots)                    │  │                │
│    ~0,5s (Argon2id)                                       │  │                │
│    → 32 octets                                            │  │                │
│                                                           │  │                │
│ 4. id = crypto.DeriverIDDepuisGraine(graine)              │  │                │
│    → "a7f3k9x2abc" (12 chars)                             │  │                │
│                                                           │  │                │
│ 5. blob_salt = crypto/rand (16 octets)                    │  │                │
│    cle = crypto.DeriverCleDepuisGraine(graine, blob_salt) │  │                │
│    → 32 octets                                            │  │                │
│                                                           │  │                │
│ 6. chiffre = AES-256-GCM(clair, cle, nonce=rand(12))      │  │                │
│    format : 0x06 ‖ blob_salt ‖ nonce ‖ scellé             │  │                │
│                                                           │  │                │
│ 7. crypto.Effacer(graine, cle)                            │  │                │
│                                                           │  │                │
│ 8. POST /v1/ardoises                                     │  │                │
│    {"contenu": base64(chiffre), "duree": "2h", ...}      │──→│ 9. Stocke      │
│                                                           │   │   {id, chiffre}│
│                      {"id": "a7f3k9x2abc", "empreinte":..}│←──│ 10.Retourne    │
│                                                           │  │                │
│ 11. Vérifier empreinte(chiffre) == réponse.empreinte      │  │                │
│                                                           │  │                │
│ 12. Afficher (stdout) :                                   │  │                │
│     chat-lune-arbre-soleil-porte                          │  │                │
│     (ou formaté en colonnes si --json)                    │  │                │
│                                                           │  │                │
│     Note: le serveur n'a JAMAIS vu les mots, ni la clé.   │  │                │
│     Il ne connaît que l'ID "a7f3k9x2abc".                │  │                │
└───────────────────────────────────────────────────────────┘  └────────────────┘
```

### 3.2 Get aveugle avec `--mots`

```
┌─ Client ─────────────────────────────────────────────────┐  ┌─ Serveur ──────┐
│                                                           │  │                │
│ 1. Saisie interactive des 5 mots :                        │  │                │
│    Invite : "Mots : "                                     │  │                │
│    (saisie masquée ou non — choix UX à trancher)          │  │                │
│    → "chat-lune-arbre-soleil-porte"                       │  │                │
│                                                           │  │                │
│ 2. Valider format (5 mots, dans la liste BIP39)           │  │                │
│                                                           │  │                │
│ 3. graine = crypto.DeriverGraine(mots)                    │  │                │
│    ~0,5s (Argon2id)                                       │  │                │
│    → 32 octets                                            │  │                │
│                                                           │  │                │
│ 4. id = crypto.DeriverIDDepuisGraine(graine)              │  │                │
│    → "a7f3k9x2abc"                                        │  │                │
│                                                           │  │                │
│ 5. GET /v1/ardoises/a7f3k9x2abc                          │──→│ 6. Cherche {id} │
│                                                           │←──│ 7. Retourne     │
│         {"contenu": base64(chiffre), "empreinte":...}      │   │    chiffre      │
│                                                           │  │                │
│ 8. Vérifier empreinte(chiffre) == réponse.empreinte       │  │                │
│                                                           │  │                │
│ 9. Décode le chiffré : version doit être 0x06             │  │                │
│    Extraire blob_salt (octets 1–16)                       │  │                │
│                                                           │  │                │
│ 10. cle = crypto.DeriverCleDepuisGraine(graine, blob_salt)│  │                │
│     → 32 octets                                           │  │                │
│                                                           │  │                │
│ 11. clair = AES-256-GCM⁻¹(scellé, cle, nonce, AAD)        │  │                │
│                                                           │  │                │
│ 12. crypto.Effacer(graine, cle)                           │  │                │
│                                                           │  │                │
│ 13. Restituer clair (stdout ou --sortie)                  │  │                │
│     + marquage si applicable                              │  │                │
└───────────────────────────────────────────────────────────┘  └────────────────┘
```

### 3.3 Push analysé avec `--mots`

```
┌─ Client ───────────────────────────────────────────────┐  ┌─ Serveur (analysé) ──────────┐
│                                                         │  │                              │
│ 1. Lire contenu                                         │  │                              │
│                                                         │  │                              │
│ 2. mots = crypto.GenererMots(5)                         │  │                              │
│    → ["chat", "lune", "arbre", "soleil", "porte"]       │  │                              │
│                                                         │  │                              │
│ 3. graine = crypto.DeriverGraine(mots)  (~0,5s)         │  │                              │
│                                                         │  │                              │
│ 4. blob_salt = crypto/rand (16 octets)                  │  │                              │
│    cle = crypto.DeriverCleDepuisGraine(graine, blob_salt)│  │                              │
│                                                         │  │                              │
│ 5. crypto.Effacer(graine)                               │  │                              │
│                                                         │  │                              │
│ 6. POST /v1/ardoises                                   │  │                              │
│    {                                                    │  │                              │
│      "contenu": base64(CLAIR),                          │  │                              │
│      "cle_chiffrement": base64(cle),   ← NOUVEAU        │  │                              │
│      "blob_salt": base64(blob_salt),   ← NOUVEAU        │─→│ 7. Analyse ICAP → favorable   │
│      "duree": "2h"                                      │  │                              │
│    }                                                    │  │                              │
│                                                         │  │ 8. id = DeriverIDDepuisCle(cle)│
│    [si id collision → 409 Conflict,                     │  │    OU NouvelIDServeur()       │
│     le client régénère mots et réessaie]                │  │    (selon stratégie retenue)   │
│                                                         │  │                              │
│                                                         │  │ 9. chiffre = AES-256-GCM(     │
│                                                         │  │      clair, cle, nonce,       │
│                                                         │  │      AAD=0x04‖blob_salt)      │
│                                                         │  │    OU AAD=0x06‖blob_salt      │
│                                                         │  │    (selon version retenue)     │
│                                                         │  │                              │
│                                                         │  │ 10. Stocke {id, chiffre}      │
│                                                         │  │ 11. Effacer(cle)              │
│                                                         │  │ 12. Effacer(clair)            │
│                                                         │  │                              │
│                    {"id": "a7f3k9x2abc", "empreinte":..} │←─│ 13. Retourne                  │
│                                                         │  │                              │
│ 14. crypto.Effacer(cle)                                 │  │                              │
│                                                         │  │                              │
│ 15. Afficher (stdout) :                                 │  │                              │
│     chat-lune-arbre-soleil-porte                        │  │                              │
└─────────────────────────────────────────────────────────┘  └──────────────────────────────┘
```

### 3.4 Get analysé avec `--mots`

**Identique au Get aveugle** (§3.2). Le client dérive l'ID et la clé depuis les mots, appelle `GET /v1/ardoises/{id}`, et déchiffre localement. La provenance serveur du chiffrement est encodée dans l'octet de version (0x06 vs 0x04). Le client de récupération n'a pas besoin de savoir si l'instance d'origine était en mode aveugle ou analysé.

### 3.5 Stratégie de collision d'ID en mode analysé

Deux options pour le serveur :

| Option | Description | Avantage | Inconvénient |
|---|---|---|---|
| **A — ID aléatoire** | Le serveur continue à générer `id` via `NouvelIDServeur()`. La clé `cle_chiffrement` est utilisée telle quelle pour le chiffrement. L'ID n'est PAS dérivé de la clé. | Zéro changement du flux serveur (sauf le chiffrement avec clé fournie). Le client reçoit l'ID dans la réponse. | Le client DOIT stocker l'ID quelque part ou le mémoriser ? Non — c'est l'étape 8 du §3.3 : le serveur retourne l'ID, et l'ID est DANS le mnémonique ? **NON** — le mnémonique n'encode que les mots. Le client ne peut pas retrouver l'ID depuis les mots seuls si l'ID est aléatoire. **Cela casse le get**. |
| **B — ID dérivé de la clé** | `id = DeriverIDDepuisCle(cle)`. Retry si collision. | Le client peut recalculer l'ID depuis les mots (mots→graine→cle→ID). Fonctionne sans état. | Change le flux serveur. L'ID n'est plus totalement décorrélé de la clé. |

**Décision** : Option B — ID dérivé de la clé. C'est le seul moyen de garder la propriété « les 5 mots suffisent ». Le serveur utilise la fonction `DeriverIDDepuisCle()` du paquet crypto.

### 3.6 Choix de l'octet de version côté serveur (analysé)

Deux sous-options :

| Option | Version | Signification |
|---|---|---|
| **B1 — CHIF-4** | `0x04` | Le serveur chiffre avec la clé fournie, mais utilise la version CHIF-4 standard. Le client doit **savoir** que c'est un schéma mots pour la dérivation. Le format du chiffré est `0x04 ‖ nonce(12) ‖ scellé` (pas de blob_salt car pas de dérivation HKDF). |
| **B2 — CHIF-5** | `0x06` | Le serveur chiffre avec la clé fournie, sous l'octet 0x06. Le blob_salt est fourni par le client (champ `blob_salt`). Le format est `0x06 ‖ blob_salt(16) ‖ nonce(12) ‖ scellé`. Cohérent avec le mode aveugle. |

**Décision** : Option B2 — CHIF-5 (0x06). Uniformité du format entre aveugle et analysé. Le blob_salt est dans le chiffré, lisible par le client de récupération qui n'a pas à savoir quel mode a produit l'ardoise.

---

## 4. Modifications du code

### 4.1 Fichiers à créer

#### `internal/crypto/mots.go` — Primitives cryptographiques du schéma CHIF-5

Ce fichier contient toutes les fonctions de génération, dérivation et encodage.

```go
// Package crypto — extension CHIF-5 (mots mnémoniques)
//
// Schéma : 5 mots BIP39 français → Argon2id → graine 256 bits
//   → HKDF(graine) → ID serveur 12 caractères [a-z2-9]
//   → HKDF(graine, blob_salt) → clé AES-256
//
// Le sel Argon2id est fixe : la diversification par blob se fait
// en aval via HKDF avec blob_salt. Ainsi Argon2id n'est appelé
// qu'une seule fois au get (~0,5s) et HKDF (microsecondes) assure
// que deux ardoises avec les mêmes mots ont des clés différentes.

package crypto

// TailleBlobSalt est la longueur du sel HKDF stocké dans l'en-tête
// du chiffré CHIF-5. Il diversifie la clé par blob sans recalculer
// Argon2id.
const TailleBlobSalt = 16

// InfoIDMots et InfoCleMots sont les étiquettes de domaine HKDF
// pour la dérivation d'ID et de clé depuis la graine.
const (
    infoIDMots  = "ardoise.pm/mots/id/v1"
    infoCleMots = "ardoise.pm/mots/chiffre/v1"
)

// selMots est le sel fixe de l'étape Argon2id. Il n'a pas besoin
// d'être secret (RFC 9106 §4). Il est fixe pour que les mêmes mots
// produisent toujours la même graine.
const selMots = "ardoise.pm/mots/v1"

// Paramètres Argon2id pour CHIF-5. Identiques à ceux de l'annexe B.
var (
    motsArgon2Temps     uint32 = 3
    motsArgon2Memoire   uint32 = 64 * 1024 // Kio
    motsArgon2Parallele uint8  = 4
    motsArgon2Longueur  uint32 = 32
)

// GenererMots produit n mots aléatoires depuis la liste BIP39
// française. Chaque mot encode 11 bits d'entropie. n est
// typiquement 5 (55 bits).
func GenererMots(n int) ([]string, error) { ... }

// MotsValides vérifie que chaque élément est présent dans la
// liste BIP39 française.
func MotsValides(mots []string) bool { ... }

// DeriverGraine applique Argon2id à la concaténation des mots
// (séparés par des tirets) avec le sel fixe selMots.
// Retourne une graine de 32 octets.
func DeriverGraine(mots []string) []byte { ... }

// DeriverIDDepuisGraine dérive l'identifiant serveur (12
// caractères [a-z2-9]) depuis la graine Argon2id via HKDF-SHA256
// avec étiquette infoIDMots, puis encodage dans l'alphabet de
// l'identifiant serveur.
func DeriverIDDepuisGraine(graine []byte) (string, error) { ... }

// DeriverIDDepuisCle dérive l'identifiant serveur directement
// depuis une clé AES-256. Utilisé par le serveur en mode analysé
// lorsque le client fournit cle_chiffrement.
// Équivalent à : DeriverIDDepuisGraine(cle) — la clé fait office
// de graine.
func DeriverIDDepuisCle(cle []byte) (string, error) { ... }

// DeriverCleDepuisGraine dérive la clé AES-256 depuis la graine
// Argon2id et le blob_salt. HKDF-SHA256 avec étiquette infoCleMots.
func DeriverCleDepuisGraine(graine, blobSalt []byte) ([]byte, error) { ... }

// encoderID derivee est la fonction interne qui transforme 32
// octets en 12 caractères de l'alphabet [a-z2-9] via un PRNG
// déterministe (HMAC-DRBG) et échantillonnage avec rejet.
func encoderID(derivee []byte) (string, error) { ... }
```

#### `internal/crypto/mots_test.go` — Tests unitaires

```
Tests :
  - TestGenererMots : génère 5 mots 1000 fois, vérifie qu'ils sont
    dans la liste BIP39, qu'ils sont tous différents (non déterministes),
    et que le format est correct.
  - TestDeriverGraine : vecteur de test avec mots connus → graine
    attendue (calculée avec une implémentation de référence).
  - TestDeriverGraineDeterministe : mêmes mots → même graine (x5).
  - TestDeriverIDDepuisGraine : vecteur fixe graine → ID attendu.
  - TestDeriverIDDepuisGraineCollisions : sur 10000 graines aléatoires,
    vérifier que les IDs sont dans l'alphabet et qu'il n'y a pas de
    biais de distribution.
  - TestDeriverCleDepuisGraine : vecteur fixe (graine, blob_salt) →
    clé attendue. Vérifier que changer blob_salt donne une clé
    différente.
  - TestMotsValides : cas valides, cas avec mot hors liste,
    cas avec moins de 5 mots, cas avec liste vide.
  - TestRoundTrip : GenererMots → DeriverGraine → DeriverID →
    chiffrer avec DeriverCle → déchiffrer → contenu identique.
  - TestFuzzingMots : fuzzer sur le parsing des mots (bytes
    aléatoires passés à MotsValides).
  - TestEffacementMemoire : vérifier que DeriverGraine et
    DeriverCleDepuisGraine retournent des []byte distincts
    (pas de partage de slice).
  - TestEncoderID : vecteurs fixes, cas limites (32 octets nuls,
    32 octets FF).
```

#### `internal/cli/mots.go` — Commandes CLI pour le mode mnémonique

```go
// Package cli — extension CHIF-5 (mots mnémoniques)
//
// Implémente les flags --mots pour push et get, la saisie
// interactive des mots, et l'affichage formaté.

package cli

// saisirMots lit 5 mots sur le terminal. L'invite est "Mots : ".
// Accepte les mots séparés par des espaces ou des tirets.
// Retourne une erreur si moins de 5 mots ou mots hors liste.
func saisirMots(ctx *Contexte) ([]string, error) { ... }

// afficherMots écrit les 5 mots sur la sortie standard.
// En mode TTY, groupe par ligne de 3-2 pour lisibilité.
func afficherMots(w io.Writer, mots []string, tty bool) { ... }

// preparerChiffrementMots gère le chiffrement CHIF-5 côté client
// (mode aveugle) : génère les mots, dérive graine/ID/clé, chiffre.
// Retourne le chiffré complet (version 0x06 ‖ blob_salt ‖ nonce ‖ scellé),
// les mots pour affichage, et la clé pour l'appelant (qui l'effacera).
func preparerChiffrementMots(clair []byte) (chiffre []byte, mots []string, cle []byte, err error) { ... }

// dechiffrerMots gère le déchiffrement CHIF-5 côté client :
// mots → graine → ID → GET → extraire blob_salt → cle → déchiffrer.
func dechiffrerMots(ctx *Contexte, cl *client.Client, mots []string) ([]byte, error) { ... }
```

#### `internal/cli/mots_test.go` — Tests d'intégration CLI

```
Tests :
  - TestSaisirMots_Valides : simulation de saisie valide.
  - TestSaisirMots_HorsListe : mot inexistant → erreur.
  - TestSaisirMots_MoinsDeCinq : 3 mots → erreur.
  - TestAfficherMots : vérifie le format de sortie (lignes, tirets).
  - TestPushGetMots_RoundTrip : test d'intégration complet —
    push --mots, get --mots, contenu identique.
  - TestPushGetMots_Aveugle : vérifie que le serveur n'a jamais
    accès aux mots (inspection du journal serveur).
  - TestPushGetMots_Analyse : round-trip avec mock ICAP favourable.
  - TestPushGetMots_CollisionID : retry côté client quand le serveur
    retourne 409 Conflict.
```

### 4.2 Fichiers à modifier

#### `internal/crypto/crypto.go`

Modifications :

1. **Ajouter la constante de version** (après la ligne 97) :
   ```go
   VersionMots byte = 0x06 // CHIF-5 — mots mnémoniques
   ```

2. **Modifier `Schema()`** (ligne 214) — ajouter `VersionMots` au switch :
   ```go
   case VersionCle, VersionMotDePasse, VersionCleMotDePasse,
        VersionServeur, VersionMultiDest, VersionMots:
   ```

3. **Modifier `BesoinCle()`** (ligne 223) — CHIF-5 nécessite la clé :
   ```go
   func BesoinCle(version byte) bool {
       return version == VersionCle || version == VersionCleMotDePasse ||
              version == VersionServeur || version == VersionMots
   }
   ```

4. **Ajouter `BesoinMots()`** :
   ```go
   func BesoinMots(version byte) bool {
       return version == VersionMots
   }
   ```

5. **Modifier `Dechiffrer()`** (ligne 244) — ajouter le cas CHIF-5 dans le switch. Le déchiffrement CHIF-5 est identique à CHIF-2/CHIF-4 (version, nonce, scellé GCM) — la seule différence est la présence du blob_salt dans l'en-tête. Le blob_salt est extrait mais ignoré par `Dechiffrer()` : c'est l'appelant qui l'utilise pour dériver la clé. `Dechiffrer()` reçoit déjà la clé dérivée.

6. **Modifier `decouper()`** (ligne 343) — ajouter le cas `VersionMots` pour extraire blob_salt :
   ```go
   func decouper(chiffre []byte) (enTete, sel, nonce, scelle []byte, err error) {
       version := chiffre[0]
       tailleSel := 0
       if version == VersionMotDePasse || version == VersionCleMotDePasse {
           tailleSel = TailleSel
       }
       if version == VersionMots {
           tailleSel = TailleBlobSalt  // 16 octets
       }
       // ... reste inchangé
   }
   ```

#### `internal/cli/push.go`

Modifications :

1. **Ajouter le flag `--mots`** dans `optionsPush` (struct et méthode `enregistrer`).

2. **Modifier `cmdPush`** : après `preparerChiffrement`, ajouter une branche `if opts.mots` qui appelle `preparerChiffrementMots` au lieu de `preparerChiffrement` standard. En mode analysé avec `--mots`, la clé et le blob_salt sont envoyés au serveur via les champs `cle_chiffrement` et `blob_salt` de la requête.

3. **Modifier `envoyerEtVerifier`** : accepter les nouveaux champs de réponse, et afficher les mots au lieu de l'identifiant formaté.

#### `internal/cli/get.go`

Modifications :

1. **Ajouter le flag `--mots`** dans `cmdGet`.

2. **Ajouter une branche** : si `--mots` est actif, ignorer l'argument positionnel IDENTIFIANT, appeler `saisirMots()`, puis `dechiffrerMots()`.

3. **Modifier la vérification de schema** : après `crypto.Schema(chiffre)`, si `crypto.BesoinMots(schema)`, s'assurer que `--mots` est actif et que le matériel est fourni.

#### `internal/server/handlers.go`

Modifications :

1. **Ajouter les champs à `requeteDepot`** (fichier `reponses.go` ou struct interne) :
   ```go
   type requeteDepot struct {
       Contenu            string `json:"contenu"`
       Duree              string `json:"duree,omitempty"`
       LectureUnique      bool   `json:"lecture_unique"`
       Pour               []string `json:"pour,omitempty"`
       MarquageComplement string `json:"marquage_complement,omitempty"`
       // NOUVEAU : pour CHIF-5 en mode analysé
       CleChiffrement     string `json:"cle_chiffrement,omitempty"` // base64, 32 octets
       BlobSalt           string `json:"blob_salt,omitempty"`       // base64, 16 octets
   }
   ```

2. **Modifier `deposerArdoise`** (ligne 130) : ajouter la validation de `CleChiffrement` et `BlobSalt` en mode analysé :
   - Si `CleChiffrement` est présent : décoder base64, vérifier len=32
   - Si `BlobSalt` est présent : décoder base64, vérifier len=16
   - Si l'un est présent sans l'autre → erreur 400
   - Si `CleChiffrement` présent mais mode=aveugle → erreur 422 (le client ne fournit pas de clé en aveugle)

3. **Modifier `traiterDepot`** (ligne 300) : accepter `cleClient` et `blobSalt` en paramètres. Si fournis :
   ```go
   func traiterDepot(inst *config.Instance, magasin store.Magasin,
       analyseur icap.Analyseur, dep *depotInterne,
       cleClient, blobSalt []byte) (*resultatDepot, error) {
       // ...
       if analyse && len(cleClient) > 0 {
           // CHIF-5 analysé : le client a fourni la clé
           var err error
           chiffre, err = crypto.ChiffrerAvecCle(VersionMots, blobSalt, cleClient, dep.Contenu)
           // ...
           // Dériver l'ID depuis la clé
           id, err = crypto.DeriverIDDepuisCle(cleClient)
           // ...
       }
   }
   ```

4. **Nouvelle fonction `ChiffrerAvecCle`** dans `crypto.go` :
   ```go
   // ChiffrerAvecCle chiffre avec une clé fournie, sous la version
   // indiquée. Pour CHIF-5 (VersionMots), le blobSalt est inclus
   // dans l'en-tête.
   func ChiffrerAvecCle(version byte, blobSalt, cle, clair []byte) ([]byte, error) {
       nonce := make([]byte, TailleNonce)
       rand.Read(nonce)
       // Pour VersionMots : en-tête = version ‖ blobSalt
       // Pour VersionServeur : en-tête = version seul
       enTete := []byte{version}
       if version == VersionMots {
           enTete = append(enTete, blobSalt...)
       }
       gcm, _ := nouveauGCM(cle)
       chiffre := make([]byte, 0, len(enTete)+len(nonce)+len(clair)+gcm.Overhead())
       chiffre = append(chiffre, enTete...)
       chiffre = append(chiffre, nonce...)
       return gcm.Seal(chiffre, nonce, clair, enTete), nil
   }
   ```

#### `internal/server/reponses.go`

Modifications :

Si le fichier existe (vérifier la structure actuelle), ajouter les champs `CleChiffrement` et `BlobSalt` à la structure `requeteDepot` (ou créer une structure dédiée).

#### `docs/man.md`

Ajouter la documentation de `--mots` dans :
- Section `OPTIONS DE DÉPÔT (push)` : description du flag
- Section `OPTIONS DE RÉCUPÉRATION (get)` : description du flag
- Section `EXEMPLES` : un exemple de push/get avec `--mots`
- Section `SÉCURITÉ` : mention du niveau de sécurité (55 bits + Argon2id) et de la TTL courte comme atténuation

---

## 5. API et structures de données

### 5.1 Requête de dépôt enrichie

```json
// POST /v1/ardoises — avec champs CHIF-5 optionnels
{
  "contenu":             "base64...",       // obligatoire
  "duree":               "2h",             // optionnel
  "lecture_unique":      true,             // optionnel
  "pour":                ["alice.durand"], // optionnel
  "marquage_complement": "urgence prod",   // optionnel
  "cle_chiffrement":     "base64...",      // optionnel (CHIF-5 analysé, 32 octets décodés)
  "blob_salt":           "base64..."       // optionnel (CHIF-5 analysé, 16 octets décodés)
}
```

### 5.2 Réponse de dépôt

Inchangée. Le serveur retourne `{"id": "a7f3k9x2abc", "empreinte": "sha256:...", "echeance": "..."}`. En mode mnémonique, la clé n'est PAS retournée par le serveur (elle est déjà connue du client).

### 5.3 Signatures des fonctions principales

```go
// === crypto/mots.go ===

// GenererMots produit n mots BIP39 français aléatoires.
func GenererMots(n int) ([]string, error)

// MotsValides vérifie que tous les mots sont dans la liste BIP39.
func MotsValides(mots []string) bool

// DeriverGraine applique Argon2id(password=mots, salt=selMots).
// Coût : ~0,5s, 64 Mio RAM.
func DeriverGraine(mots []string) []byte

// DeriverIDDepuisGraine dérive l'ID serveur (12 chars [a-z2-9]).
func DeriverIDDepuisGraine(graine []byte) (string, error)

// DeriverIDDepuisCle dérive l'ID serveur depuis une clé AES-256.
// Pour le serveur en mode analysé CHIF-5.
func DeriverIDDepuisCle(cle []byte) (string, error)

// DeriverCleDepuisGraine dérive la clé AES-256 depuis graine + blobSalt.
func DeriverCleDepuisGraine(graine, blobSalt []byte) ([]byte, error)

// === crypto/crypto.go (ajouts) ===

// ChiffrerAvecCle chiffre avec une clé fournie (pour CHIF-5 analysé).
func ChiffrerAvecCle(version byte, blobSalt, cle, clair []byte) ([]byte, error)

// BesoinMots indique si le schéma exige des mots mnémoniques.
func BesoinMots(version byte) bool

// === cli/mots.go ===

// preparerChiffrementMots : flux push CHIF-5 côté client.
func preparerChiffrementMots(clair []byte) (chiffre []byte, mots []string, cle []byte, err error)

// dechiffrerMots : flux get CHIF-5 côté client.
func dechiffrerMots(ctx *Contexte, cl *client.Client, mots []string) ([]byte, error)

// saisirMots : lit 5 mots interactivement.
func saisirMots(ctx *Contexte) ([]string, error)

// afficherMots : écrit les mots formatés.
func afficherMots(w io.Writer, mots []string, tty bool)
```

### 5.4 Liste des mots BIP39 française

La liste BIP39 française standard est chargée depuis une constante `[]string` intégrée dans `internal/crypto/liste_bip39_fr.go` (fichier autogénéré ou statique). La liste fait 2048 entrées, soit ~25 Kio de code source, acceptable.

Alternative : charger depuis `embed` au build :
```go
//go:embed bip39_french.txt
var listeBIP39Brute string
var listeBIP39 = strings.Split(strings.TrimSpace(listeBIP39Brute), "\n")
```

---

## 6. Tests à écrire

### 6.1 Tests unitaires — `internal/crypto/mots_test.go`

| Test | Description | Type |
|---|---|---|
| `TestGenererMots_Taille` | 1000 itérations, 5 mots, tous dans la liste | Déterministe |
| `TestGenererMots_Unicite` | Vérifie qu'on n'a pas 5 fois le même mot | Probabiliste |
| `TestDeriverGraine_Deterministe` | Mêmes mots → même graine (x10) | Déterministe |
| `TestDeriverGraine_Vecteur` | Vecteur de test connu (mots, graine attendue) | Déterministe |
| `TestDeriverGraine_MotsDifferents` | Mots différents → graines différentes | Probabiliste |
| `TestDeriverGraine_Memoire` | Vérifie qu'Argon2id consomme ~64 Mio | Benchmark |
| `TestDeriverIDDepuisGraine_Vecteur` | Vecteur fixe graine → ID connu | Déterministe |
| `TestDeriverIDDepuisGraine_Alphabet` | 10000 IDs, tous caractères dans `[a-z2-9]` | Déterministe |
| `TestDeriverIDDepuisGraine_Longueur` | 10000 IDs, tous font 12 caractères | Déterministe |
| `TestDeriverIDDepuisCle_Equivalent` | `DeriverIDDepuisCle(cle)` == `DeriverIDDepuisGraine(cle)` | Déterministe |
| `TestDeriverCleDepuisGraine_Vecteur` | Vecteur fixe (graine, blobSalt) → clé connue | Déterministe |
| `TestDeriverCleDepuisGraine_SaltDifferents` | Même graine, blobSalt différents → clés différentes | Déterministe |
| `TestMotsValides_OK` | 5 mots valides → true | Déterministe |
| `TestMotsValides_HorsListe` | Mot inventé → false | Déterministe |
| `TestMotsValides_MoinsDeCinq` | 3 mots → false | Déterministe |
| `TestMotsValides_Vide` | Liste vide → false | Déterministe |
| `TestRoundTrip_Chiffrement` | Mots → graine → ID → cle → chiffrer → déchiffrer → clair identique | Intégration crypto |
| `TestFuzzing_MotsValides` | Fuzzer : bytes aléatoires → pas de panic | Fuzzing |
| `TestFuzzing_DeriverGraine` | Fuzzer : []string aléatoire → pas de panic | Fuzzing |
| `TestEncoderID_Vecteurs` | Vecteurs fixes : 32 octets → ID connu | Déterministe |
| `TestEncoderID_Limites` | 32 octets nuls, 32 octets 0xFF | Déterministe |
| `TestEffacementMemoire` | Vérifier que les slices retournés sont distincts | Déterministe |
| `TestVersionMots_Decouper` | Chiffré 0x06 → decouper extrait blobSalt | Déterministe |
| `TestVersionMots_Schema` | Schema(0x06...) retourne VersionMots | Déterministe |
| `TestVersionMots_BesoinCle` | BesoinCle(VersionMots) == true | Déterministe |
| `TestVersionMots_BesoinMots` | BesoinMots(VersionMots) == true, false pour autres | Déterministe |

### 6.2 Tests d'intégration — `internal/cli/mots_test.go`

| Test | Description |
|---|---|
| `TestPushGetMots_RoundTrip_Aveugle` | Démarre serveur aveugle → push --mots → get --mots → contenu identique |
| `TestPushGetMots_RoundTrip_Analyse` | Démarre serveur analysé (mock ICAP favorable) → push --mots → get --mots → contenu identique |
| `TestPushMots_ServeurIgnoreMots` | Push aveugle --mots → le journal serveur ne contient PAS les mots |
| `TestPushMots_ServeurIgnoreCle` | Push aveugle --mots → le journal serveur ne contient PAS la clé |
| `TestGetMots_MauvaisMots` | Mots erronés → erreur (ardoise inexistante, code 5) |
| `TestGetMots_MotHorsListe` | Mot hors liste BIP39 → erreur de validation |
| `TestGetMots_BlobSaltModifie` | Chiffré altéré (blobSalt modifié) → erreur de déchiffrement |
| `TestPushMots_AnalyseDefavorable` | Mock ICAP défavorable → push --mots refusé (code 7) |
| `TestPushGetMots_AvecCache` | Push --mots, get --mots, get --cache-seul → succès |
| `TestPushGetMots_AvecMarquage` | Vérifier que le marquage est appliqué en mode --mots |
| `TestPushMots_TailleMax` | Contenu > taille_max → refus (code 8) |
| `TestAfficherMots_Format` | Vérification du format d'affichage |
| `TestSaisirMots_Interactif` | Simulation de saisie → parsing correct |
| `TestSaisirMots_AvecTirets` | "chat-lune-arbre-soleil-porte" → 5 mots |
| `TestSaisirMots_AvecEspaces` | "chat lune arbre soleil porte" → 5 mots |

### 6.3 Tests de non-régression

Tous les tests existants (`go test ./...`) doivent continuer à passer. Aucune modification des schémas CHIF-1/2/3/4/MD existants n'est autorisée. Le nouvel octet 0x06 ne doit pas altérer le comportement des autres versions.

---

## 7. Sécurité résiduelle

### 7.1 Niveau de sécurité effectif

| Scénario d'attaque | Complexité | Faisabilité en 7 jours |
|---|---|---|
| Brute-force exhaustif (espace 2^55) | 2^55 × 0,5s = 1,8 × 10^16 secondes ≈ **570 millions d'années** (1 machine) | Négligeable |
| Brute-force avec 100 000 machines spécialisées | 1,8 × 10^11 secondes ≈ **5 700 ans** pour l'espace entier | ~0,7% de couverture |
| Brute-force avec 1 000 000 machines | 1,8 × 10^10 secondes ≈ **570 ans** pour l'espace entier | ~7% de couverture |
| Attaque ciblée (ardoise spécifique connue) | Espérance = espace/2 → **285 ans** à 1M machines | ~3,5% de succès |
| Attaque par dictionnaire | Sans objet : mots générés aléatoirement, pas choisis | N/A |
| Préimage ID → mots | ID = HKDF(Argon2id(mots)). Préimage Argon2id infaisable | Négligeable |

**Conclusion** : Pour la TTL maximale de 7 jours, même un acteur étatique disposant d'un million de machines dédiées Argon2id (hypothèse extrême : 128 GiB RAM × 1M = 128 PiB de RAM totale) n'a qu'une probabilité de succès de ~3,5% par ardoise ciblée. La protection est suffisante pour une TTL de 7 jours. Niveau R−, hors contexte réglementé.

### 7.2 Ce à quoi on renonce explicitement

| Propriété | CHIF-2 (id#cle) | CHIF-5 (5 mots) | Accepté par |
|---|---|---|---|
| Entropie de la passphrase | 256 bits | 55 bits | Utilisateur |
| Résistance post-quantique | AES-256 → 128 bits (Grover) | AES-256 mais passphrase 55 bits → ~27,5 bits effectifs quantiques | Produit (non post-quantique de toute façon) |
| Indépendance ID/clé | Complète | Liés par Argon2id (préimage infaisable mais structurellement liés) | Analyse de risque |
| Absence totale d'état client | Aucun état | Aucun état non plus (les mots suffisent) | ✅ Préservé |

### 7.3 Limitations connues

1. **Pas de checksum** : Contrairement au BIP39 24 mots (8 bits SHA-256), le format 5 mots n'a pas de checksum. Une erreur de saisie produit un ID différent → ardoise inexistante (code 5). L'utilisateur doit ressaisir.

2. **Pas de recovery partiel** : Avec 24 mots BIP39, on peut retrouver le dernier mot (checksum). Avec 5 mots sans checksum, un mot oublié = 2048 combinaisons. Un mot erroné = perte définitive si l'utilisateur ne se souvient plus du mot exact.

3. **Mots en clair dans `ps`** : Si l'utilisateur passe les mots en argument de ligne de commande (ex: `ardoise get --mots chat-lune-arbre-soleil-porte`), ils seront visibles dans `ps`. Le `get --mots` DOIT utiliser la saisie interactive, comme `--mot-de-passe`. Pas d'argument positionnel pour les mots.

4. **Pas de support CHIF-1/CHIF-3 avec mots** : Les schémas combinant clé + mot de passe (CHIF-1) ou mot de passe seul (CHIF-3) ne sont pas compatibles avec `--mots`. Le flag `--mots` est exclusif avec `--mot-de-passe`.

---

## 8. Checklist d'implémentation

### Phase 1 — Primitives cryptographiques
- [ ] Créer `internal/crypto/liste_bip39_fr.go` — liste BIP39 française (2048 mots, constante)
- [ ] Créer `internal/crypto/mots.go` — toutes les primitives
- [ ] Créer `internal/crypto/mots_test.go` — tests unitaires exhaustifs
- [ ] Ajouter `VersionMots = 0x06` dans `crypto.go`
- [ ] Modifier `Schema()`, `BesoinCle()`, `decouper()`, `Dechiffrer()` dans `crypto.go`
- [ ] Ajouter `ChiffrerAvecCle()` dans `crypto.go`
- [ ] Ajouter `BesoinMots()` dans `crypto.go`
- [ ] Créer `internal/crypto/chif5_test.go` — tests spécifiques au format 0x06

### Phase 2 — Commandes CLI
- [ ] Créer `internal/cli/mots.go` — saisie, affichage, flux push/get
- [ ] Créer `internal/cli/mots_test.go` — tests d'intégration CLI
- [ ] Modifier `internal/cli/push.go` — flag `--mots`, branchement CHIF-5
- [ ] Modifier `internal/cli/get.go` — flag `--mots`, branchement CHIF-5
- [ ] Vérifier exclusivité `--mots` / `--mot-de-passe`

### Phase 3 — Serveur
- [ ] Ajouter champs `cle_chiffrement`, `blob_salt` à `requeteDepot`
- [ ] Modifier `deposerArdoise()` — validation des nouveaux champs
- [ ] Modifier `traiterDepot()` — chiffrement avec clé fournie, ID dérivé
- [ ] Tests d'intégration serveur avec mock ICAP

### Phase 4 — Documentation et finalisation
- [ ] Mettre à jour `docs/man.md`
- [ ] `go test ./...` — tous les tests passent (existants + nouveaux)
- [ ] `go vet ./...` — aucune erreur
- [ ] `go fmt ./...` — formatage conforme
- [ ] Vérifier que le Dockerfile n'est pas impacté (binaire statique, pas de nouvelle dépendance runtime)
- [ ] `./ardoise serve --verifier` — la nouvelle option CHIF-5 doit apparaître ou non dans la politique

### Phase 5 — Vérifications de sécurité
- [ ] Pas de `InsecureSkipVerify` introduit
- [ ] Pas de cleartext dans les logs ou erreurs
- [ ] `crypto.Effacer()` appelé sur toutes les graines et clés après usage
- [ ] Comparaisons en temps constant pour tous les tokens
- [ ] Les mots ne sont jamais loggés (ni client, ni serveur)
- [ ] Le serveur ne reçoit jamais les mots en mode aveugle
- [ ] Vérifier que `Dechiffrer` avec version 0x06 ne fuit pas d'information temporelle

---

## Annexe A — Entropie et nombre de mots alternatifs

Pour référence, si l'utilisateur souhaite ajuster le compromis mots/entropie :

| Mots | Entropie | Brute-force (1 machine) | Brute-force (100K machines) | Recommandation |
|---|---|---|---|---|
| 4 | 44 bits | 8 700 ans | **12 heures** | ❌ Trop faible |
| **5** | **55 bits** | **570 000 ans** | **2,8 ans** | ✅ Minimum acceptable |
| 6 | 66 bits | 36 millions d'années | 365 ans | ✅ Confortable |
| 7 | 77 bits | 2,3 milliards d'années | 23 000 ans | ✅ Très confortable |
| 8 | 88 bits | — | — | ✅ Overkill pour pastebin |

La valeur `n=5` est codée en dur dans `GenererMots(5)` et `MotsValides()` mais le code interne peut accepter un paramètre `n` pour permettre une évolution future sans réécriture.

