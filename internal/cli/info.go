package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	apiclient "ardoise.pm/internal/client"
	"ardoise.pm/internal/config"
	"ardoise.pm/internal/server"
)

const aideInfo = `usage : ardoise info [OPTIONS]

Affiche la configuration effective de l'instance : mode, mécanisme
d'identification exigé, bornes de durée de vie et de taille, régime
d'analyse, politique de rémanence, niveau de marquage. Ne dépose rien et ne
consomme aucune ardoise.
` + aideCommunes + aideAuthClient

// cmdInfo interroge GET /v1/politique sur l'instance et restitue la
// politique effective (affichage humain, ou JSON brut avec --json).
func cmdInfo(ctx *Contexte, args []string) error {
	fs := nouveauFS("info")
	var com optionsCommunes
	com.enregistrer(fs)
	var auth optionsAuthClient
	auth.enregistrer(fs)
	if err := analyserFlags(fs, args); err != nil {
		return err
	}
	if com.aide {
		afficherAide(ctx.Stdout, aideInfo)
		return nil
	}
	if err := verifierPositionnels(fs, 0, "ardoise info [OPTIONS]"); err != nil {
		return err
	}
	s := nouvelleSortie(ctx, &com)

	configClient, err := config.ChargerClient(ctx.CheminsConfigClient, ctx.Getenv)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}

	endpoint := com.endpoint
	if endpoint == "" {
		endpoint = configClient.Endpoint
	}
	if endpoint == "" {
		return erreurUsage("aucune instance indiquée : utilisez « --endpoint », la variable ARDOISE_ENDPOINT ou la configuration client")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return erreurUsage("endpoint « %s » invalide (attendu : https://hôte:port)", endpoint)
	}
	if u.Scheme != "https" {
		return erreurUsage("endpoint « %s » refusé : seul le schéma https est pris en charge, les flux sont toujours protégés par TLS", endpoint)
	}

	if premierNonVide(auth.pkcs11, configClient.PKCS11) != "" {
		return Erreurf(CodeErreur, "%s", messagePKCS11)
	}
	ac := premierNonVide(auth.ac, configClient.AC)
	certificat, cle := auth.certificat, auth.cle
	if certificat == "" && cle == "" {
		certificat, cle = configClient.Certificat, configClient.Cle
	}
	configTLS, err := configTLSClient(ac, certificat, cle)
	if err != nil {
		return Erreurf(CodeErreur, "%v", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		// Proxy volontairement absent : une instance ardoise se joint en
		// direct sur le réseau d'administration, jamais au travers d'un
		// mandataire (R10, HE-1).
		Transport: &http.Transport{TLSClientConfig: configTLS},
	}
	reponse, err := client.Get(strings.TrimSuffix(endpoint, "/") + "/v1/politique")
	if err != nil {
		if apiclient.EstRefusCertificatClient(err) {
			return Erreurf(CodeAuthRefusee,
				"certificat client requis ou refusé par l'instance : fournissez un certificat reconnu par son AC via « --certificat » et « --cle »")
		}
		return Erreurf(CodeInjoignable, "instance injoignable : %v", err)
	}
	defer reponse.Body.Close()
	corps, err := io.ReadAll(io.LimitReader(reponse.Body, 1<<20))
	if err != nil {
		return Erreurf(CodeErreur, "lecture de la réponse : %v", err)
	}
	if reponse.StatusCode != http.StatusOK {
		return Erreurf(CodePourStatutHTTP(reponse.StatusCode), "réponse inattendue de l'instance (HTTP %d)", reponse.StatusCode)
	}

	if com.json {
		fmt.Fprintln(ctx.Stdout, strings.TrimSpace(string(corps)))
		return nil
	}
	var politique config.Politique
	if err := json.Unmarshal(corps, &politique); err != nil {
		return Erreurf(CodeErreur, "réponse illisible de l'instance : %v", err)
	}
	fmt.Fprint(ctx.Stdout, rendreInfo(&politique, s))
	return nil
}

// configTLSClient construit la configuration TLS du client : AC dédiée
// (--ac, ARDOISE_AC, configuration client) ou magasin système, certificat
// client optionnel. Jamais d'InsecureSkipVerify, en aucune circonstance.
//
// Épinglage (TLS-1) : dès qu'une AC est fournie, elle devient l'unique
// autorité de confiance — RootCAs remplace intégralement le magasin
// système, sans repli. Un certificat d'instance émis par toute autre
// autorité, y compris une autorité publique par ailleurs reconnue par le
// poste, est refusé.
func configTLSClient(cheminAC, cheminCertificat, cheminCle string) (*tls.Config, error) {
	configTLS := &tls.Config{
		// TLS 1.2 minimum : une instance en TLS-3 reste joignable ; les
		// suites 1.2 sont restreintes à la liste ANSSI.
		MinVersion:   tls.VersionTLS12,
		CipherSuites: server.SuitesTLS12(),
	}
	if cheminAC != "" {
		pemAC, err := os.ReadFile(cheminAC)
		if err != nil {
			return nil, fmt.Errorf("lecture de l'autorité de certification : %v", err)
		}
		magasin := x509.NewCertPool()
		if !magasin.AppendCertsFromPEM(pemAC) {
			return nil, fmt.Errorf("autorité de certification %s : aucun certificat PEM exploitable", cheminAC)
		}
		configTLS.RootCAs = magasin
	}
	if (cheminCertificat == "") != (cheminCle == "") {
		return nil, fmt.Errorf("« --certificat » et « --cle » vont de pair")
	}
	if cheminCertificat != "" {
		certificat, err := tls.LoadX509KeyPair(cheminCertificat, cheminCle)
		if err != nil {
			return nil, fmt.Errorf("chargement du certificat client : %v", err)
		}
		configTLS.Certificates = []tls.Certificate{certificat}
	}
	return configTLS, nil
}

// rendreInfo restitue la politique à la manière de l'exemple du manuel.
func rendreInfo(p *config.Politique, s *sortie) string {
	var b strings.Builder
	ligne := func(titre, valeur string) {
		fmt.Fprintf(&b, "%s: %s\n", s.gras(padDroite(titre, 21)), valeur)
	}
	ligne("Instance", p.Instance)
	ligne("Mode", texteMode(p.Mode))
	if o, ok := p.Option(config.DimIdentification); ok {
		ligne("Identification", fmt.Sprintf("%s (%s)", o.Libelle, o.ID))
	}
	ligne("Durée de vie", fmt.Sprintf("%s maximum, %s par défaut", p.DureeMax, p.DureeDefaut))
	ligne("Taille maximale", p.TailleMax)
	ligne("Lecture unique", texteLectureUnique(p.LectureUnique))
	if o, ok := p.Option(config.DimAnalyse); ok {
		ligne("Analyse de contenu", texteAnalyse(o))
	}
	if o, ok := p.Option(config.DimRemanence); ok {
		ligne("Rémanence locale", texteCache(o))
	}
	if o, ok := p.Option(config.DimJournalisation); ok {
		ligne("Journalisation", o.Libelle)
	}
	if p.MarquageActif {
		ligne("Marquage", p.MarquageLibelle)
	} else {
		ligne("Marquage", "aucun")
	}
	return b.String()
}

func texteMode(mode string) string {
	switch mode {
	case config.ModeAveugle:
		return "aveugle (le serveur ne peut à aucun moment lire les contenus)"
	case config.ModeAnalyse:
		return "analysé (le serveur analyse les contenus déposés)"
	}
	return mode
}

func texteLectureUnique(valeur string) string {
	switch valeur {
	case config.LectureUniqueImposee:
		return "imposée à chaque dépôt"
	case config.LectureUniqueAuChoix:
		return "au choix de l'émetteur"
	case config.LectureUniqueInterdit:
		return "interdite"
	}
	return valeur
}

func texteAnalyse(o config.OptionEffective) string {
	switch o.ID {
	case "ANA-1", "ANA-2":
		return "ICAP, bloquante"
	case "ANA-3":
		return "détection de secrets côté client"
	case "ANA-4":
		return "aucune"
	}
	return o.Libelle
}

func texteCache(o config.OptionEffective) string {
	switch o.ID {
	case "CACHE-1":
		return "interdite"
	case "CACHE-2":
		return "autorisée, bornée à l'échéance"
	case "CACHE-3":
		return "libre"
	}
	return o.Libelle
}
