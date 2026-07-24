package cli

import "fmt"

// Codes de retour, exactement la table de docs/man.md (« CODES DE RETOUR »).
const (
	CodeOK                 = 0 // Succès
	CodeErreur             = 1 // Erreur générale
	CodeUsage              = 2 // Erreur d'usage
	CodeRefusPolitique     = 3 // Option refusée par la politique de l'instance
	CodeSecretDetecte      = 4 // Dépôt interrompu : secret détecté dans le contenu
	CodeIntrouvable        = 5 // Ardoise inexistante, expirée ou déjà consommée
	CodeAuthRefusee        = 6 // Authentification refusée
	CodeAnalyseDefavorable = 7 // Analyse de contenu défavorable ou indisponible
	CodeTailleDepassee     = 8 // Taille maximale dépassée
	CodeInjoignable        = 9 // Instance injoignable
)

// Erreur porte un message destiné à l'utilisateur et le code de retour du
// processus. Toute commande la retourne plutôt que d'appeler os.Exit.
type Erreur struct {
	Code    int
	Message string
}

func (e *Erreur) Error() string { return e.Message }

// Erreurf construit une Erreur formatée.
func Erreurf(code int, format string, args ...any) *Erreur {
	return &Erreur{Code: code, Message: fmt.Sprintf(format, args...)}
}

// erreurUsage construit une erreur d'usage (code 2).
func erreurUsage(format string, args ...any) *Erreur {
	return Erreurf(CodeUsage, format, args...)
}

// CodePourStatutHTTP traduit un statut HTTP de l'API en code de retour,
// selon la correspondance du manuel. Les statuts 404 et 410 se confondent
// volontairement (code 5) : l'indifférenciation prive un tiers d'un moyen
// d'inférence (docs/man.md).
func CodePourStatutHTTP(statut int) int {
	switch statut {
	case 401, 403:
		return CodeAuthRefusee
	case 404, 410:
		return CodeIntrouvable
	case 413:
		return CodeTailleDepassee
	case 422:
		return CodeRefusPolitique
	case 451:
		return CodeAnalyseDefavorable
	}
	return CodeErreur
}
