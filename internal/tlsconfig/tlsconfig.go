// Package tlsconfig rassemble les constantes et fonctions TLS partagées
// entre le serveur (internal/server) et le client (internal/cli), évitant
// que la CLI n'importe le serveur (violation de couche).
package tlsconfig

import "crypto/tls"

// SuitesTLS12 est la liste fermée des suites autorisées lorsque TLS 1.2 est
// admis (TLS-3) : ECDHE avec AES-GCM ou ChaCha20-Poly1305 exclusivement,
// conformément au guide TLS de l'ANSSI. TLS 1.3 impose ses propres suites.
func SuitesTLS12() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// MessagePKCS11 : le support matériel exige un module PKCS#11 natif,
// incompatible avec la contrainte de binaire statique sans cgo du produit.
// L'option est acceptée pour que le manuel reste exact, mais refusée avec
// une explication plutôt qu'ignorée en silence.
const MessagePKCS11 = "PKCS#11 non pris en charge dans cette version (nécessite cgo, incompatible binaire statique — voir dossier de risques)"
