package config

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// reTaille accepte un entier suivi d'une unité binaire : « o » (octet),
// « Kio » (1024 octets) ou « Mio » (1024² octets), avec une espace
// facultative (« 256Kio », « 256 Kio »).
var reTaille = regexp.MustCompile(`^([0-9]+) ?(o|Kio|Mio)$`)

// ParseTaille analyse une taille au format du manuel (« 256Kio »).
// La taille doit être strictement positive.
func ParseTaille(s string) (int64, error) {
	m := reTaille.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("taille « %s » invalide (attendu : un entier suivi de « o », « Kio » ou « Mio », par exemple « 256Kio »)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("taille « %s » invalide : %v", s, err)
	}
	if n == 0 {
		return 0, fmt.Errorf("taille « %s » invalide : elle doit être strictement positive", s)
	}
	mult := int64(1)
	switch m[2] {
	case "Kio":
		mult = 1 << 10
	case "Mio":
		mult = 1 << 20
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("taille « %s » invalide : valeur démesurée", s)
	}
	return n * mult, nil
}

// FormatTaille restitue une taille en octets sous sa forme la plus lisible
// (« 256 Kio », « 1 Mio », « 512 o »).
func FormatTaille(octets int64) string {
	switch {
	case octets >= 1<<20 && octets%(1<<20) == 0:
		return fmt.Sprintf("%d Mio", octets/(1<<20))
	case octets >= 1<<10 && octets%(1<<10) == 0:
		return fmt.Sprintf("%d Kio", octets/(1<<10))
	}
	return fmt.Sprintf("%d o", octets)
}
