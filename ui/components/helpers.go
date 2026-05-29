package components

import (
	"fmt"
	"strings"
)

// intToString converts an integer to a string for HTML attribute values.
func intToString(n int) string {
	return fmt.Sprintf("%d", n)
}

// formatNumber formats a float with the given decimals and comma thousands
// separators (e.g. 1234567.5 -> "1,234,567.5").
func formatNumber(value float64, decimals int) string {
	formatted := fmt.Sprintf("%.*f", decimals, value)
	if value < 1000 {
		return formatted
	}
	intPart, decPart := formatted, ""
	if i := strings.IndexByte(formatted, '.'); i >= 0 {
		intPart, decPart = formatted[:i], formatted[i:]
	}
	var b strings.Builder
	for i, digit := range intPart {
		if i > 0 && (len(intPart)-i)%3 == 0 {
			b.WriteRune(',')
		}
		b.WriteRune(digit)
	}
	b.WriteString(decPart)
	return b.String()
}
