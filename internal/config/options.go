package config

import "time"

// Option relie une valeur de configuration à son identifiant du document
// d'architecture (docs/dat.md §5) et à son niveau selon la convention du
// guide ANSSI-PA-022 : R (état de l'art), R- et R-- (alternatives de niveau
// moindre), R+ (renforcement).
type Option struct {
	ID      string
	Niveau  string
	Libelle string
}

// optionInvalide est retournée lorsqu'une valeur de configuration ne
// correspond à aucune option connue ; la validation a déjà signalé le champ.
var optionInvalide = Option{ID: "?", Niveau: "?", Libelle: "valeur invalide"}

// §5.2 — Identification et authentification.
var optionsAuth = map[string]Option{
	"mtls-materiel": {ID: "AUTH-1", Niveau: "R+", Libelle: "certificat client sur support matériel, AC interne"},
	"mtls":          {ID: "AUTH-2", Niveau: "R", Libelle: "certificat client, AC interne"},
	"jeton":         {ID: "AUTH-3", Niveau: "R-", Libelle: "jeton du service d'identité de l'entité"},
	"declaratif":    {ID: "AUTH-4", Niveau: "R--", Libelle: "identification déclarative, non authentifiée"},
}

// §5.4 — Protection des contenus.
var optionsChiffrement = map[string]Option{
	"cle":     {ID: "CHIF-2", Niveau: "R", Libelle: "clé aléatoire par ardoise, chiffrement local"},
	"serveur": {ID: "CHIF-4", Niveau: "R--", Libelle: "chiffrement par le serveur après analyse (cécité a posteriori)"},
}

// §5.9 — Rémanence côté client.
var optionsCache = map[string]Option{
	"interdit": {ID: "CACHE-1", Niveau: "R", Libelle: "interdite"},
	"borne":    {ID: "CACHE-2", Niveau: "R-", Libelle: "bornée à l'échéance de l'ardoise"},
	"libre":    {ID: "CACHE-3", Niveau: "R--", Libelle: "libre, purge sur demande"},
}

func (i *Instance) optionAuth() Option {
	if o, ok := optionsAuth[i.Auth.Mecanisme]; ok {
		return o
	}
	return optionInvalide
}

func (i *Instance) optionChiffrement() Option {
	if o, ok := optionsChiffrement[i.Contenu.Chiffrement]; ok {
		return o
	}
	return optionInvalide
}

func (i *Instance) optionCache() Option {
	if o, ok := optionsCache[i.Cache.Politique]; ok {
		return o
	}
	return optionInvalide
}

// optionRetention combine le support et le régime de lecture unique
// (docs/dat.md §5.3) : RET-1 est « memoire » avec lecture unique imposée.
func (i *Instance) optionRetention() Option {
	switch i.Retention.Support {
	case "memoire":
		if i.Retention.LectureUnique == LectureUniqueImposee {
			return Option{ID: "RET-1", Niveau: "R+", Libelle: "mémoire vive, destruction à la première lecture imposée"}
		}
		return Option{ID: "RET-2", Niveau: "R", Libelle: "mémoire vive"}
	case "disque-chiffre":
		return Option{ID: "RET-3", Niveau: "R-", Libelle: "disque chiffré, effacement à l'échéance"}
	}
	return optionInvalide
}

// optionTTL découle de la borne duree_max (docs/dat.md §5.3).
func (i *Instance) optionTTL() Option {
	d := i.Retention.DureeMax
	libelle := FormatDuree(d) + " maximum"
	switch {
	case d <= 0:
		return optionInvalide
	case d <= time.Hour:
		return Option{ID: "TTL-1", Niveau: "R+", Libelle: libelle}
	case d <= 24*time.Hour:
		return Option{ID: "TTL-2", Niveau: "R", Libelle: libelle}
	case d <= PlafondTTL:
		return Option{ID: "TTL-3", Niveau: "R-", Libelle: libelle}
	}
	return optionInvalide
}

// optionAnalyse découle du mode et des réglages d'analyse (docs/dat.md §5.5).
func (i *Instance) optionAnalyse() Option {
	if i.Mode == ModeAnalyse {
		if i.Analyse.ICAPRegles != "" {
			return Option{ID: "ANA-1", Niveau: "R+", Libelle: "analyse ICAP bloquante, règles de l'entité, détection de secrets côté client"}
		}
		return Option{ID: "ANA-2", Niveau: "R", Libelle: "analyse ICAP synchrone bloquante (fail-closed)"}
	}
	if i.Analyse.SecretsClient == "desactive" {
		return Option{ID: "ANA-4", Niveau: "R--", Libelle: "aucune analyse"}
	}
	return Option{ID: "ANA-3", Niveau: "R-", Libelle: "détection de secrets côté client"}
}

// optionJournal découle de la destination et du chaînage (docs/dat.md §5.6).
func (i *Instance) optionJournal() Option {
	switch {
	case estCollecteur(i.Journal.Destination) && i.Journal.Chainage:
		return Option{ID: "JOURN-1", Niveau: "R+", Libelle: "collecteur central, entrées chaînées"}
	case estCollecteur(i.Journal.Destination):
		return Option{ID: "JOURN-2", Niveau: "R", Libelle: "collecteur central"}
	case i.Journal.Destination == "fichier":
		return Option{ID: "JOURN-3", Niveau: "R-", Libelle: "journal local, collecte périodique"}
	case i.Journal.Destination == "aucun":
		return Option{ID: "JOURN-4", Niveau: "R--", Libelle: "aucune journalisation"}
	}
	return optionInvalide
}

// optionTransport découle de la version TLS minimale (docs/dat.md §5.7).
// TLS-1 (R+) suppose une encapsulation IPsec hors périmètre du produit :
// la meilleure option configurable est TLS-2.
func (i *Instance) optionTransport() Option {
	suffixe := ""
	if i.Transport.Epinglage {
		suffixe = ", épinglage actif"
	}
	switch i.Transport.VersionMin {
	case "1.3":
		return Option{ID: "TLS-2", Niveau: "R", Libelle: "TLS 1.3" + suffixe}
	case "1.2":
		return Option{ID: "TLS-3", Niveau: "R-", Libelle: "TLS 1.2" + suffixe}
	}
	return optionInvalide
}

// optionMarquage découle de l'activation du marquage (docs/dat.md §5.8).
func (i *Instance) optionMarquage() Option {
	if i.Marquage.Actif {
		return Option{ID: "MARQ-1", Niveau: "R", Libelle: "« " + i.Marquage.Libelle + " »"}
	}
	return Option{ID: "MARQ-2", Niveau: "R--", Libelle: "aucun marquage"}
}
