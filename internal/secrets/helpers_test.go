package secrets

import "strings"

// stringsRepeat repeats s count times (test helper from the source repo).
func stringsRepeat(s string, count int) string {
	return strings.Repeat(s, count)
}
