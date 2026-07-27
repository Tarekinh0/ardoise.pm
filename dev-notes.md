# Dev Notes — Peer Review Fixes (commit `1ca3687`)

## Modified files

- `internal/cli/autoinstall.go` — PR-001, PR-002, PR-003
- `internal/cli/autoinstall_test.go` — PR-001 (rename tests)

## PR-001 — Renommer `peutEcrire` → `assurerRepertoireAccessible`

**Rationale** : `peutEcrire` faisait `MkdirAll` en plus du test d'écriture — le nom mentait
sur la pureté de la fonction (side effects cachés). Renommage pour refléter le comportement
réel : la fonction assure que le répertoire parent existe et est accessible, en le créant
si nécessaire.

**Changements** :
- Fonction + godoc renommés dans `autoinstall.go`
- Les 2 appelants dans `installerBinaire` mis à jour
- Les 3 fonctions de test renommées :
  - `TestPeutEcrireFichierExistant` → `TestAssurerRepertoireAccessibleFichierExistant`
  - `TestPeutEcrireRepertoireAccessible` → `TestAssurerRepertoireAccessibleRepertoireAccessible`
  - `TestPeutEcrireRepertoireCree` → `TestAssurerRepertoireAccessibleRepertoireCree`
- Messages d'erreur dans les tests mis à jour avec le nouveau nom

## PR-002 — TOCTOU dans `installerPageMan`

**Rationale** : Entre `os.Stat` (vérification d'existence) et `os.WriteFile` (écriture),
un processus concurrent peut créer le fichier. `os.WriteFile` écrase silencieusement.

**Solution** : Remplacement de `os.WriteFile` par `os.OpenFile` avec `O_WRONLY|O_CREATE|O_EXCL`.
Le flag `O_EXCL` garantit l'atomicité au niveau noyau : si le fichier a été créé entre le
`Stat` et l'`OpenFile`, l'appel échoue et on retourne sans erreur (comportement idempotent
préservé).

## PR-003 — Garde `pageManuel` vide

**Rationale** : Si l'embed (`//go:embed manpage.md`) casse au build (fichier absent, erreur
de génération), `pageManuel` est une string vide. Sans garde, `installerPageMan` écrit
silencieusement une page de manuel vide.

**Solution** : Ajout d'un early return `if pageManuel == "" { return }` en haut de
`installerPageMan`. Aucun effet sur le fonctionnement normal (la page est embeddée et non
vide au build valide).

## How to test

```bash
# Binary
go build ./...
go vet ./...
go test -count=1 ./...

# Container
docker build -t ardoise-test .
docker run --rm ardoise-test --version
```

## Gaps or remaining risks

- `installerPageMan` teste `pageManuel == ""` mais ne distingue pas l'absence d'embed
  d'une page légitimement vide. Acceptable : une page vide n'a pas de sens fonctionnel.
- `assurerRepertoireAccessible` a toujours un TOCTOU entre le `CreateTemp` de test
  d'écriture et l'écriture réelle dans `faireLienOuCopie`, mais c'est inhérent au
  design (on ne peut pas verrouiller un répertoire). Le pire cas est un échec silencieux,
  ce qui est la sémantique attendue de l'auto-install.
