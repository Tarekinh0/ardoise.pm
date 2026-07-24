package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// reDuree limite les durées aux unités entières h, m et s (« 30m », « 2h »,
// « 24h », « 1h30m »). Les unités inférieures à la seconde et les valeurs
// décimales sont refusées : elles n'ont aucun sens pour une durée de vie.
var reDuree = regexp.MustCompile(`^([0-9]+h)?([0-9]+m)?([0-9]+s)?$`)

// ParseDuree analyse une durée de vie au format du manuel (« 30m », « 2h »,
// « 24h »). La durée doit être strictement positive.
func ParseDuree(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || !reDuree.MatchString(s) {
		return 0, fmt.Errorf("durée « %s » invalide (attendu : un entier suivi de « h », « m » ou « s », par exemple « 30m » ou « 24h »)", s)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("durée « %s » invalide : %v", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("durée « %s » invalide : elle doit être strictement positive", s)
	}
	return d, nil
}

// FormatDuree restitue une durée sous la forme compacte du manuel
// (« 24h », « 1h30m », « 45m »).
func FormatDuree(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Round(time.Second)
	h := int64(d / time.Hour)
	m := int64((d % time.Hour) / time.Minute)
	s := int64((d % time.Minute) / time.Second)
	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}
