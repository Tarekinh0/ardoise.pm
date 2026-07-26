# ardoise.pm

Service interne d'echange ephemere de texte pour equipes d'administration.

Ardoise est un pastebin interne — un binaire unique Go qui depose et recupere
des blocs de texte sur une instance maitrisee. Le contenu est chiffre, horodate,
et detruit a echeance. Aucune archive, aucun listage, aucune recherche.

**Statut : V1 implementee, testee.**  
30/31 tests d'integration PASS. Deployable depuis un reseau d'administration
standard jusqu'aux environnements relevant de l'II 901 (Diffusion Restreinte)
et de l'IGI 1300 (classifie).

---

## Schemas de chiffrement

| Schema | Octet | Principe | Conformite |
|---|---|---|---|
| **CHIF-2** | `0x01` | Cle AES-256 aleatoire (`id#cle`) | R (II 901, IGI 1300) |
| **CHIF-4** | `0x04` | Chiffrement serveur (mode analyse) | R (II 901, IGI 1300) |
| **CHIF-5** | `0x06` | 5 mots BIP39 + Argon2id (`--mots`) | R− (hors contexte reglemente) |
| **CHIF-MD** | `0x05` | Multi-destinataires (ECDH) | R (II 901, IGI 1300) |

CHIF-1 et CHIF-3 (mot de passe, cle+motdepasse) ont ete retires en V1.
Details : [`docs/dat.md` §5.4](docs/dat.md) et annexe B.

---

## Deux modes

| Mode | Principe | Conformite |
|---|---|---|
| **Aveugle** | Chiffrement de bout en bout — le serveur ne voit jamais le clair | Reseau d'administration interne (par.11.1 PA-022) |
| **Analyse** | Contenu soumis a ICAP avant chiffrement — le serveur chiffre apres verdict | Systeme d'echange externe (R58, par.11.2 PA-022) |

Le mode est impose par l'instance. Le client l'affiche avant tout envoi et ne
peut pas l'affaiblir.

---

## Usage

```bash
# Deposer
echo "extrait de log" | ardoise
tail -200 /var/log/nginx/error.log | ardoise -t 30m -b

# Deposer avec mots mnemoniques (CHIF-5)
echo "message" | ardoise --mots

# Recuperer
ardoise get a7f3k9x2#Zt8mQ4v...

# Recuperer avec mots
ardoise get --mots

# Recuperer sans exposer l'identifiant dans ps
ardoise get - < identifiant.txt

# Consulter la politique de l'instance
ardoise info -e https://ardoise.adm.interne:8443

# Purger le cache local
ardoise purge --tout
```

L'identifiant contient la cle de dechiffrement apres le `#`. Ce fragment n'est
jamais transmis au serveur. Un identifiant complet equivaut au contenu — il
se transmet par un canal maitrise.

---

## Architecture

- **Binaire unique** Go (compilation statique) — roles client et serveur
- **Chiffrement** AES-256-GCM, cle unique par ardoise, Argon2id pour CHIF-5
- **Transport** TLS 1.3, mTLS, jetons, identification declarative (R+ a R--)
- **Duree de vie** configurable (1h a 7j), destruction a la premiere lecture
- **Analyse** ICAP synchrone bloquante (RFC 3507, fail-closed) en mode analyse
- **Throttling** GET limite a 30 requetes/min par IP
- **Journalisation** metadonnees uniquement (jamais le contenu), chainage optionnel
- **Marquage** automatique du niveau de sensibilite
- **Cache client** optionnel, purge a echeance, sans cle
- **Conteneur** Red Hat UBI micro, non-root, rootfs en lecture seule
- **Distribution** paquets signes, builds reproductibles, installation hors ligne

Architecture complete : [`docs/dat.md`](docs/dat.md).  
Manuel : [`docs/man.md`](docs/man.md).

---

## Deploiement

```bash
# Serveur
ardoise serve --config /etc/ardoise/ardoise.json

# Conteneur
docker run -v /etc/ardoise:/etc/ardoise:ro ardoise:latest
```

Image OCI sur Red Hat UBI micro, sans privileges, `CAP_DROP ALL`.

---

## Installation

Paquets signes, builds reproductibles, installation hors ligne native.

```bash
# Verifier un binaire
ardoise version

# Verifier une configuration sans demarrer
ardoise serve --config ardoise.json --verifier
```

---

## Licence

Apache 2.0 + Commons Clause — usage, modification et redistribution libres ;
vente interdite. Voir [ADR-012](docs/dat.md).

---

## Roadmap

[`docs/implementation/backlog/ardoise-v1-roadmap.md`](docs/implementation/backlog/ardoise-v1-roadmap.md).

Etat : **V1 implementee** — 10 sprints executes, 30/31 tests integration PASS.
