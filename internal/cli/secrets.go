package cli

import (
	"fmt"

	"ardoise.pm/internal/secrets"
)

// Modes de détection de secrets, du plus strict au plus permissif.
const (
	secretsBloquer   = "bloquer"
	secretsDemander  = "demander"
	secretsSignaler  = "signaler"
	secretsDesactive = "desactive"
)

// rangSecrets ordonne les modes par sévérité croissante ; un mode inconnu
// (instance d'une autre version) vaut « demander », le défaut du manuel.
func rangSecrets(mode string) int {
	switch mode {
	case secretsBloquer:
		return 3
	case secretsDemander:
		return 2
	case secretsSignaler:
		return 1
	case secretsDesactive:
		return 0
	}
	return 2 // inconnu : prudence du défaut « demander »
}

// modeSecretsEffectif combine l'exigence de l'instance (analyse.
// secrets_client, annoncée par la politique) et la demande du client
// (« --secrets ») : le PLUS STRICT des deux l'emporte, le client ne pouvant
// jamais affaiblir l'instance ni l'instance ignorer un durcissement local.
//
//	instance \ --secrets   (absent)    bloquer   demander   signaler
//	───────────────────────────────────────────────────────────────────
//	bloquer                bloquer     bloquer   bloquer    bloquer
//	demander               demander    bloquer   demander   demander
//	signaler               signaler    bloquer   demander   signaler
//	desactive              desactive   bloquer   demander   signaler
//
// « desactive » n'est donc effectif que si l'instance le déclare ET que
// l'utilisateur n'a rien demandé ; « bloquer » imposé par l'instance
// l'emporte sur tout — y compris « --sans-confirmation », qui ne skippe
// que la question du mode « demander », jamais un refus.
func modeSecretsEffectif(instance, drapeau string) string {
	rang := rangSecrets(instance)
	if drapeau != "" && rangSecrets(drapeau) > rang {
		rang = rangSecrets(drapeau)
	}
	switch rang {
	case 3:
		return secretsBloquer
	case 2:
		return secretsDemander
	case 1:
		return secretsSignaler
	}
	return secretsDesactive
}

// libelleDetection traduit un type de détection vers son libellé.
func libelleDetection(type_ string) string {
	switch type_ {
	case secrets.TypeClePrivee:
		return "clé privée"
	case secrets.TypeJWT:
		return "jeton JWT"
	}
	return "secret"
}

// controlerSecrets applique la détection locale de secrets (ANA-3, ES-12)
// au contenu, AVANT tout chiffrement et tout envoi. Retourne nil si le
// dépôt peut se poursuivre, une Erreur (code 4) sinon.
//
// Les refus et la liste des détections des modes « bloquer » et
// « demander » s'affichent toujours ; seul l'avertissement du mode
// « signaler » est un message informatif, supprimable par « --silencieux ».
func controlerSecrets(ctx *Contexte, s *sortie, clair []byte, modeEffectif string, sansConfirmation bool) error {
	if modeEffectif == secretsDesactive {
		return nil
	}
	detections := secrets.Detecter(clair)
	if len(detections) == 0 {
		return nil
	}

	lister := func(toujours bool) {
		for _, d := range detections {
			ligne := fmt.Sprintf("ardoise : secret détecté : %s, ligne %d (« %s »)", libelleDetection(d.Type), d.Ligne, d.Extrait)
			if toujours {
				fmt.Fprintln(ctx.Stderr, ligne)
			} else {
				s.infof("%s", ligne)
			}
		}
	}

	switch modeEffectif {
	case secretsBloquer:
		// Un blocage ne se contourne pas, « --sans-confirmation » compris :
		// lorsque l'instance impose « bloquer », aucune option locale ne
		// l'affaiblit.
		lister(true)
		return Erreurf(CodeSecretDetecte,
			"dépôt interrompu : %d secret(s) détecté(s) dans le contenu — un authentifiant relève d'un coffre-fort, pas d'une ardoise (ES-12)", len(detections))
	case secretsDemander:
		lister(true)
		if sansConfirmation {
			// « --sans-confirmation » ne skippe que la question : les
			// détections ci-dessus restent affichées.
			return nil
		}
		if ctx.Confirmer == nil {
			return Erreurf(CodeSecretDetecte,
				"dépôt interrompu : %d secret(s) détecté(s) et aucun terminal pour confirmer — utilisez « --sans-confirmation » pour les traitements automatisés dont le contenu est maîtrisé", len(detections))
		}
		accepte, err := ctx.Confirmer(fmt.Sprintf("Poursuivre le dépôt malgré %d secret(s) détecté(s) ? [o/N] ", len(detections)))
		if err != nil {
			return Erreurf(CodeSecretDetecte, "dépôt interrompu : %v", err)
		}
		if !accepte {
			return Erreurf(CodeSecretDetecte, "dépôt interrompu : secret détecté dans le contenu, confirmation refusée")
		}
		return nil
	default: // signaler
		lister(false)
		s.infof("ardoise : avertissement : %d secret(s) détecté(s), dépôt poursuivi (« signaler »)", len(detections))
		return nil
	}
}
