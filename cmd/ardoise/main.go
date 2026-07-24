// Commande ardoise : client et serveur du service interne d'échange
// éphémère de texte (voir docs/man.md et docs/dat.md).
//
// Ce point d'entrée est volontairement minimal : toute la logique vit dans
// internal/cli (ADR-001 : binaire unique client + serveur).
package main

import (
	"os"

	"ardoise.pm/internal/cli"
)

func main() {
	os.Exit(cli.Executer(cli.ContexteSysteme(os.Args[1:])))
}
