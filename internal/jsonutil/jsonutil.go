// Package jsonutil expose un décodage JSON strict partagé entre plusieurs
// paquets du produit : tables de configuration (internal/config), annuaires
// de clés publiques (internal/cli), etc. La règle est uniforme — tout champ
// inconnu et tout contenu excédentaire après l'objet racine est une erreur.
//
// Extrait de internal/config/instance.go en PR-101 : le paquet config ne
// doit pas être le dépositaire d'un utilitaire JSON générique utilisé par
// des consommateurs sans rapport avec la configuration d'instance.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
)

// DecoderStrict décode du JSON en refusant tout champ inconnu et tout
// contenu excédentaire après l'objet racine. La règle est la même que celle
// des configurations d'instance.
func DecoderStrict(donnees []byte, cible any) error {
	dec := json.NewDecoder(bytes.NewReader(donnees))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cible); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("contenu excédentaire après l'objet racine")
	}
	return nil
}
