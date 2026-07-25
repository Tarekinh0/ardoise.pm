package config

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Dimensions de sécurité de la politique effective (docs/dat.md §5).
const (
	DimIdentification = "identification"
	DimContenu        = "contenu"
	DimConservation   = "conservation"
	DimDureeDeVie     = "duree_de_vie"
	DimRemanence      = "remanence_client"
	DimAnalyse        = "analyse"
	DimJournalisation = "journalisation"
	DimTransport      = "transport"
	DimMarquage       = "marquage"
)

// OptionEffective est une option retenue, telle qu'exposée par
// GET /v1/politique et « serve --politique ».
type OptionEffective struct {
	Dimension string `json:"dimension"`
	ID        string `json:"id"`
	Niveau    string `json:"niveau"`
	Libelle   string `json:"libelle"`
}

// Politique est la politique effective d'une instance : les options retenues
// avec leur identifiant et leur niveau, plus les bornes opposables au client.
// C'est le corps de la réponse GET /v1/politique, la sortie de
// « serve --politique », et la matière de « ardoise info » (ES-4, ADR-002).
type Politique struct {
	Instance string `json:"instance"`
	Mode     string `json:"mode"`
	// Identification est le mécanisme exigé par l'instance (« mtls-materiel »,
	// « mtls », « jeton » ou « declaratif ») : le client le lit avant toute
	// opération pour préparer le matériel correspondant — en particulier, les
	// en-têtes d'identification déclarative (AUTH-4) ne sont émis que si
	// l'instance les attend.
	Identification string `json:"identification"`
	// DestinatairesAdmis annonce si l'instance accepte la désignation de
	// destinataires (« --pour ») : refusée sous identification déclarative,
	// l'identité du lecteur y étant falsifiable (DestinatairesAdmissibles).
	// Le client la lit avant tout dépôt pour refuser localement, jamais un
	// contournement silencieux (ES-4).
	DestinatairesAdmis bool `json:"destinataires_admis"`
	// CachePolitique est la politique de rémanence côté client déclarée par
	// l'instance (ADR-013) : « interdit » (CACHE-1), « borne » (CACHE-2) ou
	// « libre » (CACHE-3). Le client ne peut pas l'outrepasser.
	CachePolitique  string            `json:"cache_politique"`
	Options         []OptionEffective `json:"options"`
	DureeMax        string            `json:"duree_max"`
	DureeDefaut     string            `json:"duree_defaut"`
	TailleMax       string            `json:"taille_max"`
	TailleMaxOctets int64             `json:"taille_max_octets"`
	LectureUnique   string            `json:"lecture_unique"`
	SecretsClient   string            `json:"secrets_client"`
	MarquageActif   bool              `json:"marquage_actif"`
	MarquageLibelle string            `json:"marquage_libelle,omitempty"`
	ConformeII901   bool              `json:"conforme_ii901"`
	EcartsII901     []string          `json:"ecarts_ii901,omitempty"`
}

// Option retourne l'option effective de la dimension demandée.
func (p *Politique) Option(dimension string) (OptionEffective, bool) {
	for _, o := range p.Options {
		if o.Dimension == dimension {
			return o, true
		}
	}
	return OptionEffective{}, false
}

// dimensions ordonnées comme dans la sortie de « serve --verifier »
// (docs/man.md, section EXEMPLES).
var titresDimensions = []struct {
	dimension string
	titre     string
}{
	{DimIdentification, "Identification"},
	{DimContenu, "Contenu"},
	{DimConservation, "Conservation"},
	{DimDureeDeVie, "Durée de vie"},
	{DimRemanence, "Rémanence client"},
	{DimAnalyse, "Analyse"},
	{DimJournalisation, "Journalisation"},
	{DimTransport, "Transport"},
	{DimMarquage, "Marquage"},
}

// Politique construit la politique effective de l'instance.
func (i *Instance) Politique() Politique {
	ecarts := i.EcartsII901()
	p := Politique{
		Instance:           i.Nom,
		Mode:               i.Mode,
		Identification:     i.Auth.Mecanisme,
		DestinatairesAdmis: i.DestinatairesAdmissibles(),
		CachePolitique:     i.Cache.Politique,
		DureeMax:           FormatDuree(i.Retention.DureeMax),
		DureeDefaut:        FormatDuree(i.Retention.DureeDefaut),
		TailleMax:          FormatTaille(i.Contenu.TailleMax),
		TailleMaxOctets:    i.Contenu.TailleMax,
		LectureUnique:      i.Retention.LectureUnique,
		SecretsClient:      i.Analyse.SecretsClient,
		MarquageActif:      i.Marquage.Actif,
		MarquageLibelle:    i.Marquage.Libelle,
		ConformeII901:      len(ecarts) == 0,
		EcartsII901:        ecarts,
	}
	ajouter := func(dimension string, o Option) {
		p.Options = append(p.Options, OptionEffective{
			Dimension: dimension,
			ID:        o.ID,
			Niveau:    o.Niveau,
			Libelle:   o.Libelle,
		})
	}
	ajouter(DimIdentification, i.optionAuth())
	ajouter(DimContenu, i.optionChiffrement())
	ajouter(DimConservation, i.optionRetention())
	ajouter(DimDureeDeVie, i.optionTTL())
	ajouter(DimRemanence, i.optionCache())
	ajouter(DimAnalyse, i.optionAnalyse())
	ajouter(DimJournalisation, i.optionJournal())
	ajouter(DimTransport, i.optionTransport())
	ajouter(DimMarquage, i.optionMarquage())
	return p
}

// EcartsII901 confronte la configuration aux minima exigés pour les systèmes
// relevant de l'II 901 (docs/dat.md §6.1). La liste vide signifie que la
// configuration atteint ou dépasse chaque minimum.
func (i *Instance) EcartsII901() []string {
	var ecarts []string
	if i.optionAuth().ID == "AUTH-4" {
		ecarts = append(ecarts, "identification : AUTH-4 (déclarative) sous le minimum AUTH-3")
	}
	if id := i.optionTTL().ID; id == "TTL-3" || id == "?" {
		ecarts = append(ecarts, "durée de vie : au-delà du plafond de 24h (TTL-2) fixé par R57")
	}
	if i.Mode == ModeAveugle && i.optionChiffrement().ID == "CHIF-3" {
		ecarts = append(ecarts, "protection des contenus : CHIF-3 sous le minimum CHIF-2 en mode aveugle")
	}
	if i.optionAnalyse().ID == "ANA-4" {
		ecarts = append(ecarts, "analyse : ANA-4 sous le minimum ANA-3 (détection de secrets, R35)")
	}
	if id := i.optionJournal().ID; id == "JOURN-3" || id == "JOURN-4" {
		ecarts = append(ecarts, fmt.Sprintf("journalisation : %s sous le minimum JOURN-2 (collecteur central, R46/R47)", id))
	}
	if i.optionTransport().ID == "TLS-3" {
		ecarts = append(ecarts, "transport : TLS-3 (TLS 1.2) sous le minimum TLS-2 (TLS 1.3, R24)")
	}
	if i.optionMarquage().ID == "MARQ-2" {
		ecarts = append(ecarts, "marquage : MARQ-2 sous le minimum MARQ-1 (marquage automatique)")
	}
	if i.optionCache().ID == "CACHE-3" {
		ecarts = append(ecarts, "rémanence client : CACHE-3 exclue (CACHE-1 exigé, CACHE-2 admissible)")
	}
	return ecarts
}

// RenduVerification produit la sortie de « serve --verifier » : la politique
// effective avec l'identifiant et le niveau de chaque option, les écarts aux
// minima II 901, puis les incohérences détectées (docs/man.md).
func (i *Instance) RenduVerification(problemes []Probleme) string {
	p := i.Politique()
	var b strings.Builder
	b.WriteString("Politique effective :\n")
	for _, td := range titresDimensions {
		o, _ := p.Option(td.dimension)
		fmt.Fprintf(&b, "  %s %s %s %s\n",
			padDroite(td.titre, 17),
			padDroite(o.ID, 8),
			padDroite("("+o.Niveau+")", 5),
			o.Libelle)
	}
	if p.ConformeII901 {
		b.WriteString("Configuration conforme aux minima II 901.")
	} else {
		b.WriteString("Configuration NON conforme aux minima II 901 :\n")
		for _, e := range p.EcartsII901 {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}
	if len(problemes) == 0 {
		if p.ConformeII901 {
			b.WriteString(" Aucune incohérence détectée.\n")
		} else {
			b.WriteString("Aucune incohérence détectée.\n")
		}
	} else {
		if p.ConformeII901 {
			b.WriteString("\n")
		}
		b.WriteString("Incohérences détectées :\n")
		for _, pr := range problemes {
			fmt.Fprintf(&b, "  - %s\n", pr)
		}
	}
	return b.String()
}

// padDroite complète une chaîne à droite jusqu'à n caractères (comptés en
// runes : les accents ne cassent pas l'alignement).
func padDroite(s string, n int) string {
	manque := n - utf8.RuneCountInString(s)
	if manque <= 0 {
		return s
	}
	return s + strings.Repeat(" ", manque)
}
