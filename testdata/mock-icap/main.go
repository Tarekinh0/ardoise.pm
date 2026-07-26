// mock-icap est un serveur ICAP minimal pour les tests d'intégration
// docker-compose. Il répond favorablement (204) à toutes les requêtes
// REQMOD, sans analyser le contenu. Usage exclusif pour les tests —
// ne jamais déployer en production.
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "1344"
	}
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}
	addr := listenAddr + ":" + port

	ecouteur, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("ecoute ICAP maquette : %v", err)
	}
	defer ecouteur.Close()
	log.Printf("maquette ICAP à l'écoute sur %s (toujours favorable)", addr)
	log.Printf("  (LISTEN_ADDR=%s, PORT=%s)", listenAddr, port)

	for {
		conn, err := ecouteur.Accept()
		if err != nil {
			log.Printf("accept : %v", err)
			continue
		}
		go traiter(conn)
	}
}

func traiter(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 65536)
	var totalBuf bytes.Buffer
	total := 0
	const maxICAPReq = 1 << 20 // 1 Mio — borne de sécurité
	// Lire la requête REQMOD entière (ligne statut + en-têtes + corps chunked).
	// Le tampon accumulé est conservé entre les lectures afin de repérer le
	// terminateur « 0\r\n\r\n » même lorsqu'il chevauche deux lectures
	// (PR-108).
	terminateur := []byte("0\r\n\r\n")
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("lecture : %v", err)
			}
			break
		}
		total += n
		if total > maxICAPReq {
			log.Printf("requête ICAP trop volumineuse (%d octets), abandon", total)
			return
		}
		totalBuf.Write(buf[:n])
		if bytes.HasSuffix(totalBuf.Bytes(), terminateur) || bytes.Contains(totalBuf.Bytes(), terminateur) {
			break
		}
	}
	// Répondre 204 — toujours favorable
	fmt.Fprintf(conn, "ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n")
	log.Printf("REQMOD traité → 204 favorable")
}
