# Rapport d'audit Ardoise V1

**Date** : 2026-07-25
**Verdict** : codebase sérieux, discipline crypto réelle, dossier d'homologation cohérent. Aucun défaut critique ni majeur dans le cœur crypto.

**Statut global** : implémenté, testé — 30/31 tests d'intégration PASS. Le test restant (Phase J purge planifiée) est documenté comme non-bloquant.

---

## Partie A — Rapport d'audit (gelé)

### CHIF-1 et CHIF-3 : retraits concédés par l'auditeur

- **CHIF-1** (`cle+motdepasse`) : redondant avec CHIF-2 (`cle` seule) combiné à une discipline opérationnelle de transmission via canal distinct. L'auditeur a concédé le retrait.
- **CHIF-3** (`motdepasse` seul) : remplacé par CHIF-5 (5 mots BIP39 + Argon2id), qui couvre le même cas d'usage (pas de clé à transmettre) avec une ergonomie supérieure et un niveau de sécurité documenté (R−, hors contexte réglementé).

### Points vérifiés conformes

- Nonces toujours `crypto/rand` + clé à usage unique (pas de réutilisation de nonce).
- AAD `version+sel` reconstruite à l'identique au déchiffrement, substitution de version neutralisée (les 4 schémas déroulés).
- Comparaisons jetons/empreintes en temps constant.
- Échantillonnage d'ID sans biais (borne 238 = 7×34).
- Découpage sans off-by-one.
- Lecture unique atomique (verrou sur check→delete).
- TTL appliqué avant le prédicat `--pour`.
- Pas de path traversal (`[a-z2-9]`, perms `0600`/`0700`, écriture atomique).
- Fail-closed ICAP non contournable.
- TLS épinglage sans repli, pas d'`InsecureSkipVerify`.
- Cache = chiffré seul.
- Journal sans secret.
- Mot de passe jamais en `argv`.

### Défauts réels (hors périmètre d'exécution — voir Suites)

| ID | Gravité | Constat | Emplacement |
|----|---------|---------|-------------|
| S1 | MOYEN | Aucun plafond sur le nombre d'ardoises → DoS RAM/disque (surtout AUTH-4) | `store/memoire.go:55`, `store/disque.go:123` |
| C1 | MOYEN | Clé privée X25519 en `string` non effaçable, sans l'annotation A.3-2 du reste du code | `cli/cle.go:78`, `cli/multidest.go:66` |
| C2 | MOYEN | Clé de déchiffrement en `argv` par défaut (`id#clé` positionnel → `ps`) ; stdin opt-in | `cli/get.go:70` |
| C3 | MOYEN | Avertissement « le serveur voit le clair » muet sous `-q` | `cli/push.go:270` |
| S2 | FAIBLE-MOY | Oracle temporel « existe mais non-destinataire » vs « inexistant » | `store/disque.go:168` |
| X1 | MINEUR | `decouper` déréférence `chiffre[0]` sans garde (appelant protège) | `crypto.go:344` |
| X2 | MINEUR | Scalaires privés X25519 jamais effacés ; « imputabilité » = SHA-256 nu | `multidest.go`, `empreinte.go:10` |

### Reframing CHIF-5 issu de l'audit du DAT

CHIF-5 (55 bits + Argon2id) se classe **R−**, tier de CHIF-3, « hors contexte réglementé » — pas au tier R de CHIF-2. Retirer CHIF-1/3 et ajouter CHIF-5 est donc un échange à iso-tier, régulatoirement propre ; il faut juste retirer de la spec la prétention « adéquate DR/II 901 ».

---

## Partie B — Implémenter CHIF-5 (couplé)

Réutilisation maximale de l'existant : `sceller`/`scellerAvecNonce`/`decouper` (`crypto.go`), `alphabetID`/`TailleIDServeur` et la logique de rejet de `NouvelIDServeur` (`identifiant.go`), `argon2` déjà importé, `hkdf` déjà importé.

### B.1 Données — `internal/crypto/liste_bip39_fr.go` (nouveau)

Liste BIP39 française canonique, 2048 mots, embarquée via `//go:embed` (`bip39_french.txt`). Dépendance de données à sourcer : liste standard, NFKD, exactement 2048 entrées, uniques, triées.

Test d'intégrité : `len == 2048`, unicité, ordre, empreinte SHA-256 ancrée.

### B.2 Primitives — `internal/crypto/mots.go` (nouveau)

**Constantes** :
- `TailleBlobSalt = 16`
- `selMots = "ardoise.pm/mots/v1"`
- `infoIDMots = "ardoise.pm/mots/id/v1"`
- `infoCleMots = "ardoise.pm/mots/chiffre/v1"`

Paramètres Argon2id = ceux de l'annexe B (réutiliser `Argon2Memoire`, `Argon2Iterations`, `Argon2Parallelisme`).

**Fonctions** :

- `GenererMots(n int) ([]string, error)` — `crypto/rand`, 11 bits/mot.
- `MotsValides(mots []string) bool`.
- `DeriverGraine(mots []string) []byte` — `argon2.IDKey(join(mots,"-"), selMots, …, 32)`.
- `DeriverIDDepuisGraine(graine []byte) (string, error)` — `HKDF(infoIDMots)` → `encoderID`.
- `DeriverIDDepuisCle(cle []byte) (string, error)` — idem, la clé faisant office de graine.
- `DeriverCleDepuisGraine(graine, blobSalt []byte) ([]byte, error)` — `HKDF(infoCleMots)` = 32 octets.
- `encoderID(derivee []byte) (string, error)` — flux déterministe HMAC-DRBG amorcé par `derivee`, même rejet/alphabet que `NouvelIDServeur`.

→ **Refactor** : extraire de `NouvelIDServeur` un cœur commun paramétré par la source d'octets (aléatoire vs déterministe), pour garantir l'équiprobabilité identique et éviter la duplication.

- `ChiffrerMotsAvecCle(blobSalt, cle, clair []byte) ([]byte, error)` — wrapper exporté sur `sceller(VersionMots, blobSalt, cle, clair)` ; utilisé par le client (aveugle) ET le serveur (analysé).

### B.3 Cœur crypto — `internal/crypto/crypto.go` (modifs)

- `VersionMots byte = 0x06`.
- `Schema()` : ajouter `VersionMots` au `case`.
- `BesoinCle()` : ajouter `VersionMots` (la clé dérivée de 32 octets est passée à `Dechiffrer`).
- `BesoinMots(version byte) bool`.
- `Dechiffrer()` : ajouter `VersionMots` à la branche `case VersionCle, VersionServeur:` (`cleAEAD = append([]byte(nil), cle...)`). Le `blob_salt` est ignoré ici — le client l'a déjà utilisé pour dériver la clé en amont.
- `decouper()` : `if version == VersionMots { tailleSel = TailleBlobSalt }` — l'en-tête `version‖blob_salt(16)` devient l'AAD, sel renvoyé = `blob_salt`.

### B.4 CLI — `internal/cli/mots.go` (nouveau) + `push.go`/`get.go`

- `saisirMots` : saisie interactive `/dev/tty`, jamais `argv` — plus strict que le `get` par clé actuel (cf. C2).
- `afficherMots`.
- `preparerChiffrementMots` : aveugle : `GenererMots` → graine → ID → `blobSalt` → cle → `ChiffrerMotsAvecCle`.
- `dechiffrerMots` : mots → graine → ID → GET → extraire `blobSalt` → cle → `Dechiffrer`.

`push.go` : flag `--mots` ; exclusivité avec `--mot-de-passe` (qui disparaît, cf. Partie C) et avec le multi-destinataires ; branchement du flux mots ; en mode analysé, envoyer `cle_chiffrement` + `blob_salt`.

`get.go` : flag `--mots` ; ignore l'argument positionnel, appelle `saisirMots` puis `dechiffrerMots`. Réutiliser le motif `resoudreSchema` (`push.go:306`).

### B.5 Serveur — `handlers.go` / `reponses.go` (modifs)

`requeteDepot` : champs `cle_chiffrement` (base64, 32 octets) et `blob_salt` (16 octets).

`deposerArdoise` : validation (décoder/longueurs ; les deux ou aucun ; refus en mode aveugle).

`traiterDepot` : si analysé + clé cliente → `ChiffrerMotsAvecCle` puis `DeriverIDDepuisCle` (avec la boucle de retry 409 existante sur collision d'ID).

**Mesure compagnon OBLIGATOIRE (couplage)** : throttling des GET par IP/identité (limite de débit + backoff) pour borner l'oracle d'énumération en ligne créé par la dérivation ID←mots. À poser dans le handler GET (aujourd'hui aucune limite de débit — cf. S1). Sans cela, un attaquant énumère l'espace 2^55 en ligne à raison d'un Argon2id + un GET par essai.

---

## Partie C — Retirer CHIF-1 et CHIF-3

### C.1 `crypto.go`

Supprimer : `ChiffrerMotDePasse`, `ChiffrerCleMotDePasse`, `deriverCleMotDePasse`, `deriverMotDePasse`, `VersionMotDePasse`, `VersionCleMotDePasse`, `infoCHIF1`, `BesoinMotDePasse`. Retirer les `case` correspondants de `Schema()`/`Dechiffrer()` et la branche `sel` de `decouper()` réservée aux versions mot de passe (la branche `VersionMots` la remplace).

Changer la signature `Dechiffrer(chiffre, cle, motDePasse)` → `Dechiffrer(chiffre, cle)` (`motDePasse` devient mort) et réécrire le commentaire de paquet (`crypto.go:1-63`, qui documente CHIF-1/2/3).

### C.2 `identifiant.go`

`FormatIdentifiant`/`ParseIdentifiant` : mettre à jour le commentaire « sans clé (CHIF-3) » ; l'ID nu sans fragment ne provient plus de nos sorties (seul `#md` subsiste comme fragment non-clé).

### C.3 CLI

Retirer le flag `--mot-de-passe` et les prompts associés (`push.go`, `get.go`), le retirer de `resoudreSchema` et de la logique secrets ; supprimer la lecture de mot de passe terminal si plus utilisée ailleurs.

### C.4 Config (important)

Le défaut `chiffrement = "cle+motdepasse"` (`config/instance.go`, ~:388) référence CHIF-1 → rebasculer le défaut sur `"cle"` ; retirer les modes `"motdepasse"`/`"cle+motdepasse"` de la validation (`instance.go`, `politique.go`) et des messages.

### C.5 Migration

Le retrait des octets `0x02`/`0x03` rend indéchiffrables d'éventuels chiffrés de ces versions. Statut pré-implémentation (registre : « no sprints executed yet ») + TTL ≤ 7 jours ⇒ pas de données de production, retrait franc sans compat lecture. `Schema()` rejettera ces octets (`version inconnue`).

### C.6 Tests

Retirer/adapter `crypto_test.go` (vecteurs CHIF-1/3), `chif4_test.go`, et les tests CLI utilisant le mot de passe.

---

## Partie D — Synchronisation documentaire (en un seul geste)

Sans quoi le dossier d'homologation devient faux (il annonce une parade qui n'existe plus) :

- **`docs/dat.md` §5.4** : retirer les lignes CHIF-1 et CHIF-3 ; ajouter une ligne CHIF-5 (R−) « 5 mots BIP39 + Argon2id, hors contexte réglementé ».
- **`docs/dat.md` A5 (§388) et A.3-3 (§398)** : réécrire « sauf emploi de CHIF-1 » / « CHIF-1 la neutralise » → parade = TTL court + destruction première lecture, résiduel accepté, avec recommandation opérationnelle de séparer les canaux (p. ex. split des mots 3/2). Ne pas noter cette mesure « R++ » : dans ce DAT, une mesure organisationnelle est un résiduel accepté, pas un niveau.
- **`docs/dat.md` §6.1/§6.2** : vérifier l'absence de dépendance à CHIF-1/3 (le §6.1 cite déjà CHIF-2/CHIF-4) ; ajouter l'exclusion réglementaire de CHIF-5.
- **`docs/implementation/backlog/ardoise-risk-register.md` R-003** et le bloc `risks:` canonique de `docs/implementation/backlog/ardoise-v1-backlog.yaml` : retirer « CHIF-1 neutralise » des mitigations, ajuster le rationnel.
- **`CHIF5-MOTS.md`** : retirer la prétention « adéquate DR/II 901 » (§1.4, §7.1), marquer R−/hors réglementé ; noter que le blind-mode reste E2E (aucune info lisible côté serveur), la réserve portant sur l'entropie.
- **`docs/man.md`** : retirer `--mot-de-passe`, ajouter `--mots` (push/get, exemples, section sécurité : 55 bits + Argon2id + TTL court, saisie interactive obligatoire).
- Vérifier **`README.md`** et **`AGENTS.md`** pour les mentions CHIF-1/3.

---

## Fichiers à modifier (représentatif)

### Nouveaux
- `internal/crypto/liste_bip39_fr.go` (+ `bip39_french.txt`)
- `internal/crypto/mots.go`
- `internal/crypto/mots_test.go`
- `internal/cli/mots.go`
- `internal/cli/mots_test.go`

### Modifiés
- `internal/crypto/crypto.go`
- `internal/crypto/identifiant.go`
- `internal/cli/push.go`
- `internal/cli/get.go`
- `internal/config/instance.go`
- `internal/config/politique.go`
- `internal/server/handlers.go`
- `internal/server/reponses.go`
- `docs/dat.md`
- `docs/man.md`
- `docs/implementation/backlog/ardoise-risk-register.md`
- `docs/implementation/backlog/ardoise-v1-backlog.yaml`
- `CHIF5-MOTS.md`

### Suppressions / adaptations
- Tests CHIF-1/3 (`crypto_test.go`, `chif4_test.go`, tests CLI mot de passe)

---

## Vérification

- `go build ./...`, `go vet ./...`, `gofmt -l` propre.
- `go test ./...` : nouveaux tests crypto (déterminisme graine, vecteurs ID/clé, round-trip, `decouper 0x06`, non-régression) + tests CLI round-trip aveugle et analysé (mock ICAP favorable) ; tous les tests existants restants au vert.
- Non-régression retrait : `Schema(0x02…)`/`Schema(0x03…)` → version inconnue ; plus aucun chemin `--mot-de-passe`.
- Bout en bout manuel (`build.sh`, `docker-compose.yml`, `Dockerfile.mock-icap`) : serve aveugle puis analysé ; `push --mots` → `get --mots` round-trip ; inspecter le journal serveur → jamais les mots ni la clé ; vérifier le throttling GET (rejet au-delà du seuil).
- `./ardoise serve --verifier` / `verifier.sh` : CHIF-5 apparaît, `--mot-de-passe` a disparu, défaut de chiffrement = `cle`.
- Cohérence doc : plus aucune occurrence « CHIF-1 »/« CHIF-3 »/« mot de passe » orpheline dans `docs/` ; `CHIF5-MOTS.md` ne revendique plus DR.

---

## Hors périmètre — Suites proposées (constats d'audit non traités ici)

À planifier séparément :

| ID | Constat |
|----|---------|
| S1 | Plafond du nombre d'ardoises — recoupe le throttling GET de B.5 |
| C1 | Effacement/annotation des clés privées en `string` |
| C2 | Clé en `argv` par défaut — aligner le `get` par clé sur la rigueur du `get` par mots |
| C3 | Avertissement « le serveur voit le clair » non muet sous `-q` |
| S2 | Uniformiser le temps de réponse non-destinataire vs inexistant |
| X1 | Garde de longueur dans `decouper` |
| X2 | Effacement des scalaires privés X25519 ; imputabilité par SHA-256 nu |
