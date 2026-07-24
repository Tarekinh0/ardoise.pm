// Package marquage applique le marquage de sensibilité en tête des contenus
// restitués (docs/dat.md §5.8, ES-11, MARQ-1/MARQ-2).
//
// Le marquage est appliqué CÔTÉ CLIENT, à la restitution : en mode aveugle
// le serveur ne détient que du chiffré et ne peut rien préfixer — le
// libellé de l'instance et le complément de l'émetteur (« --marquage »)
// voyagent donc dans la réponse de récupération, et c'est « ardoise get »
// qui les place en tête du clair déchiffré. MARQ-2 : rien n'est préfixé.
//
// # Format
//
// La ligne de marquage, volontairement simple et repérable par grep :
//
//	=== LIBELLE ===
//	=== LIBELLE — complément ===
//
// suivie d'un saut de ligne, puis du contenu inchangé. Le libellé est celui
// de l'instance (marquage.libelle), jamais remplacé par le complément
// (docs/man.md, « --marquage ») ; le complément le complète après un tiret
// cadratin. En sortie « --json », le marquage voyage dans des champs
// distincts et le contenu reste vierge.
package marquage

// EnTete construit la ligne de marquage terminée par un saut de ligne :
// « === LIBELLE ===\n » ou « === LIBELLE — complément ===\n ». Libellé
// vide : aucune ligne (chaîne vide).
func EnTete(libelle, complement string) string {
	if libelle == "" {
		return ""
	}
	if complement != "" {
		return "=== " + libelle + " — " + complement + " ===\n"
	}
	return "=== " + libelle + " ===\n"
}

// Appliquer place la ligne de marquage en tête du contenu (MARQ-1). Le
// contenu lui-même n'est jamais modifié, seulement préfixé.
func Appliquer(libelle, complement string, contenu []byte) []byte {
	entete := EnTete(libelle, complement)
	if entete == "" {
		return contenu
	}
	resultat := make([]byte, 0, len(entete)+len(contenu))
	resultat = append(resultat, entete...)
	return append(resultat, contenu...)
}
