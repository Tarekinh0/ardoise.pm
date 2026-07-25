#!/bin/sh
# verifier.sh — Vérification d'intégrité hors ligne pour ardoise.pm
# Ce script vérifie la signature détachée et l'empreinte SHA-256
# du binaire ardoise. Il n'effectue AUCUNE connexion réseau.
# (SRQ-P002-6, DPO-P-002-5, DIST-1)
#
# Usage : sh verifier.sh
#
# Prérequis :
#   - openssl (présent sur toute station d'administration durcie)
#   - python3 (optionnel, pour l'affichage structuré du SBOM)
#
# Fichiers attendus dans le répertoire courant :
#   - ardoise          (binaire)
#   - ardoise.sig      (signature détachée Ed25519)
#   - ardoise.pub      (clef publique Ed25519)
#   - ardoise.spdx.json (SBOM au format SPDX)

set -euo pipefail

# Vérification de la version d'OpenSSL (PR-111) :
# openssl pkeyutl -verify -rawin nécessite OpenSSL 3.0+.
# Sur les systèmes avec OpenSSL 1.1, la vérification échoue sans diagnostic clair.
if ! openssl version | grep -qE "OpenSSL [3-9][0-9]*\.|LibreSSL"; then
    echo "ERREUR : OpenSSL 3.0+ (ou LibreSSL équivalent) est requis pour la vérification Ed25519."
    echo "Version détectée : $(openssl version 2>&1)"
    exit 10
fi

# L'empreinte SHA-256 de référence est gravée dans ce script.
# Cette valeur est mise à jour automatiquement lors de chaque release.
# En développement, le placeholder __RELEASE_SHA256__ est remplacé par
# le workflow .github/workflows/release.yml au moment de la publication
# du binaire signé. Le fichier commité n'est pas fonctionnel en l'état :
# il est conçu pour être consommé depuis une archive de release.
PINNED_SHA256="__RELEASE_SHA256__"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "=== Ardoise — Vérification d'intégrité hors ligne ==="
echo ""

# 1. Présence des fichiers
echo "[1/4] Vérification des fichiers..."
for f in ardoise ardoise.sig ardoise.pub ardoise.spdx.json; do
    if [ ! -f "$f" ]; then
        echo "${RED}ERREUR : fichier requis « $f » absent.${NC}"
        exit 1
    fi
done
echo "  OK : tous les fichiers sont présents."

# 2. Empreinte SHA-256
echo "[2/4] Vérification de l'empreinte SHA-256..."
if [ "$PINNED_SHA256" = "__RELEASE_SHA256__" ]; then
    echo "${RED}ERREUR : ce script n'est pas un artefact de release.${NC}"
    echo "  L'empreinte de référence __RELEASE_SHA256__ est un placeholder de développement."
    echo "  Le binaire NE peut PAS être vérifié — ce script doit être consommé depuis"
    echo "  une archive de release officielle, où le placeholder est remplacé par"
    echo "  l'empreinte SHA-256 du binaire signé."
    echo "  N'exécutez PAS ce binaire sans vérification d'intégrité."
    exit 4
else
    COMPUTED=$(sha256sum ardoise | cut -d' ' -f1)
    if [ "$COMPUTED" != "$PINNED_SHA256" ]; then
        echo "${RED}ERREUR : l'empreinte SHA-256 ne correspond pas.${NC}"
        echo "  Attendu  : $PINNED_SHA256"
        echo "  Calculé  : $COMPUTED"
        exit 2
    fi
    echo "  OK : empreinte vérifiée."
fi

# 3. Signature détachée Ed25519
echo "[3/4] Vérification de la signature Ed25519..."
if ! openssl pkeyutl -verify -rawin -in ardoise -sigfile ardoise.sig -inkey ardoise.pub -pubin >/dev/null 2>&1; then
    echo "${RED}ERREUR : la signature détachée est invalide.${NC}"
    echo "  Le binaire n'est pas authentique — ne l'exécutez pas."
    exit 3
fi
echo "  OK : signature valide."

# 4. Résumé du SBOM (SPDX)
echo "[4/4] Résumé du SBOM (SPDX)..."
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys
try:
    with open('ardoise.spdx.json') as f:
        sbom = json.load(f)
    name = sbom.get('name', 'inconnu')
    pkgs = sbom.get('packages', [{}])
    ver = pkgs[0].get('versionInfo', '?') if pkgs else '?'
    deps = len(pkgs)
    print(f'  Nom          : {name}')
    print(f'  Version      : {ver}')
    print(f'  Dépendances  : {deps}')
    print(f'  Format       : SPDX-{sbom.get(\"spdxVersion\", \"?\")}')
except Exception as e:
    print(f'  SBOM présent (ardoise.spdx.json) — {e}')
" 2>/dev/null || echo "  SBOM présent dans ardoise.spdx.json"
else
    echo "  SBOM présent dans ardoise.spdx.json"
fi

echo ""
echo "${GREEN}=== Vérification réussie ===${NC}"
echo "Le binaire ardoise est intègre et authentique."
echo "Vous pouvez l'installer : sudo install -m 0755 ardoise /usr/local/bin/"
