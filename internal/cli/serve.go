package cli

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
)

const aideServe = `usage : ardoise serve --config FICHIER [OPTIONS]

Démarre une instance. La configuration déclare le mode et l'ensemble des
options de sécurité ; le serveur la fait respecter (ADR-002).

Options de serveur :
  -c, --config FICHIER   fichier de configuration de l'instance (obligatoire)
      --verifier         analyse la configuration, affiche la politique
                         effective (niveaux R/R-/R--/R+), signale toute
                         incohérence, puis quitte sans démarrer
      --politique        affiche la politique effective au format JSON
                         et quitte (preuve de configuration)
      --ecoute ADRESSE   surcharge l'adresse et le port d'écoute
` + aideCommunes

func cmdServe(ctx *Contexte, args []string) error {
	fs := nouveauFS("serve")
	var com optionsCommunes
	com.enregistrer(fs)
	var cheminConfig, ecoute string
	var verifier, politique bool
	fs.StringVar(&cheminConfig, "config", "", "")
	fs.StringVar(&cheminConfig, "c", "", "")
	fs.BoolVar(&verifier, "verifier", false, "")
	fs.BoolVar(&politique, "politique", false, "")
	fs.StringVar(&ecoute, "ecoute", "", "")

	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideServe)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise serve --config FICHIER [OPTIONS]"); err != nil {
		return err
	}
	if cheminConfig == "" {
		return erreurUsage("l'option « --config » est obligatoire")
	}
	s := nouvelleSortie(ctx, &com)

	instance, problemes, err := config.Charger(cheminConfig)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}

	if verifier {
		// Contrôle de conformité : politique effective, écarts aux minima
		// II 901, incohérences. Quitte sans démarrer (0 si cohérente).
		if _, errEcriture := ctx.Stdout.Write([]byte(instance.RenduVerification(problemes))); errEcriture != nil {
			return Erreurf(CodeErreur, "écriture de la sortie : %v", errEcriture)
		}
		if len(problemes) > 0 {
			return Erreurf(CodeErreur, "la configuration comporte %d incohérence(s)", len(problemes))
		}
		return nil
	}

	if len(problemes) > 0 {
		messages := make([]string, 0, len(problemes))
		for _, p := range problemes {
			messages = append(messages, "  - "+p.String())
		}
		return Erreurf(CodeErreur, "configuration invalide, démarrage refusé :\n%s", strings.Join(messages, "\n"))
	}

	if politique {
		// Preuve de configuration versable telle quelle à un dossier
		// d'homologation (docs/man.md, CONFORMITÉ).
		return ecrireJSONSortie(ctx.Stdout, instance.Politique())
	}

	serveur, err := server.Nouveau(instance, ecoute)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}
	if err := serveur.Ecouter(); err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}
	s.infof("instance « %s » : écoute sur https://%s (mode %s)", instance.Nom, serveur.Adresse(), instance.Mode)

	ctxSignaux, arreter := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer arreter()
	if err := serveur.Servir(ctxSignaux); err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}
	s.infof("instance « %s » : arrêt propre", instance.Nom)
	return nil
}
