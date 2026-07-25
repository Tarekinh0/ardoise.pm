package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"ardoise.pm/internal/crypto"
	"ardoise.pm/internal/jsonutil"
)

// chargerAnnuaire lit l'annuaire de clés publiques X25519 des destinataires
// (CHIF-MD, ADR-014 cas a) : un fichier JSON strict associant chaque
// identité à sa clé publique en base64, par exemple :
//
//	{ "alice.durand": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=" }
//
// L'annuaire ne porte que des clés PUBLIQUES : sa confidentialité n'est pas
// un enjeu, son intégrité si — il est destiné à être poussé par la
// télédistribution de l'entité, comme la configuration client. Tout écart
// de forme est une erreur : aucune clé approximative n'entre en service.
func chargerAnnuaire(chemin string) (map[string][]byte, error) {
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("annuaire de clés publiques : %w", err)
	}
	var table map[string]string
	if err := decoderStrictJSON(donnees, &table); err != nil {
		return nil, fmt.Errorf("annuaire de clés publiques %s : %v", chemin, err)
	}
	annuaire := make(map[string][]byte, len(table))
	for identite, cleTexte := range table {
		if identite == "" {
			return nil, fmt.Errorf("annuaire de clés publiques %s : identité vide", chemin)
		}
		cle, err := decoderCle32(cleTexte)
		if err != nil {
			return nil, fmt.Errorf("annuaire de clés publiques %s : clé de « %s » invalide (attendu : 32 octets X25519 en base64 ou hexadécimal)", chemin, identite)
		}
		annuaire[identite] = cle
	}
	return annuaire, nil
}

// clePriveeDestinataire lit la clé privée X25519 du poste
// (cle_privee_ardoise, ARDOISE_CLE_PRIVEE) : 32 octets en base64 ou en
// hexadécimal, fichier aux droits 0600 au plus — un droit de groupe ou
// d'autrui est un refus, comme pour la clé de magasin. Le matériel reste
// en []byte ; l'appelant l'efface après usage (crypto.Effacer).
func clePriveeDestinataire(chemin string) ([]byte, error) {
	infos, err := os.Stat(chemin)
	if err != nil {
		return nil, fmt.Errorf("clé privée de destinataire : %w", err)
	}
	if mode := infos.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("clé privée de destinataire %s : droits %04o trop larges (0600 au plus exigé)", chemin, mode)
	}
	donnees, err := os.ReadFile(chemin)
	if err != nil {
		return nil, fmt.Errorf("clé privée de destinataire : %w", err)
	}
	defer crypto.Effacer(donnees)
	cle, err := decoderCle32(string(bytes.TrimSpace(donnees)))
	if err != nil {
		return nil, fmt.Errorf("clé privée de destinataire %s : 32 octets X25519 en base64 ou hexadécimal attendus", chemin)
	}
	return cle, nil
}

// decoderCle32 décode une clé de 32 octets exprimée en hexadécimal (64
// caractères) ou en base64 (standard ou brut).
func decoderCle32(texte string) ([]byte, error) {
	texte = strings.TrimSpace(texte)
	if len(texte) == 64 {
		if cle, err := hex.DecodeString(texte); err == nil {
			return cle, nil
		}
	}
	for _, encodage := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if cle, err := encodage.DecodeString(texte); err == nil && len(cle) == 32 {
			return cle, nil
		}
	}
	return nil, fmt.Errorf("clé illisible")
}

// destinatairesChiffrement décide du chiffrement multi-destinataires d'un
// dépôt « --pour » en mode aveugle (ADR-014, cas a). La cryptographie ne
// s'applique que lorsque CHAQUE destinataire individuel a une clé publique
// dans l'annuaire :
//
//   - un GROUPE (« @… ») fait toujours retomber sur la seule vérification
//     serveur : l'expansion des groupes appartient à l'instance (table
//     auth.groupes), le client ne la connaît pas et ne saurait envelopper
//     la clé pour des membres qu'il ignore ;
//   - une identité SANS clé dans l'annuaire fait de même : chiffrer pour
//     les seuls destinataires connus rendrait le contenu illisible aux
//     autres — le repli est signalé, jamais silencieux.
//
// Le champ « pour » part vers l'instance DANS TOUS LES CAS : la
// vérification serveur demeure (défense en profondeur), le chiffrement
// multi-destinataires la complète — il protège aussi contre une instance
// compromise, ce que la vérification serveur seule ne peut pas.
func destinatairesChiffrement(s *sortie, pour []string, annuaire map[string][]byte) []crypto.DestinataireMD {
	if len(pour) == 0 || annuaire == nil {
		return nil
	}
	destinataires := make([]crypto.DestinataireMD, 0, len(pour))
	for _, d := range pour {
		if strings.HasPrefix(d, "@") {
			s.infof("Groupe %s désigné : désignation appliquée par l'instance seule (l'expansion des groupes appartient à l'annuaire de l'entité)", d)
			return nil
		}
		cle, ok := annuaire[d]
		if !ok {
			s.infof("Aucune clé publique pour « %s » dans l'annuaire : désignation appliquée par l'instance seule, sans chiffrement multi-destinataires", d)
			return nil
		}
		destinataires = append(destinataires, crypto.DestinataireMD{Identite: d, ClePublique: cle})
	}
	return destinataires
}

// decoderStrictJSON décode du JSON en refusant tout champ inconnu et tout
// contenu excédentaire (même règle que les configurations).
func decoderStrictJSON(donnees []byte, cible any) error {
	return jsonutil.DecoderStrict(donnees, cible)
}
