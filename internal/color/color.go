package color

import (
	"fmt"
	"strconv"
)

const (
	RST  = "\033[0m"
	CYN  = "\033[36m"
	GRN  = "\033[32m"
	RED  = "\033[31m"
	YEL  = "\033[33m"
	BLU  = "\033[34m"
	MAG  = "\033[35m"
	GRY  = "\033[90m"
	BOLD = "\033[1m"
	DIM  = "\033[2m"
)

func Status(code int) string {
	switch {
	case code >= 200 && code < 300:
		return GRN + strconv.Itoa(code) + RST
	case code >= 300 && code < 400:
		return BLU + strconv.Itoa(code) + RST
	case code >= 400 && code < 500:
		return YEL + strconv.Itoa(code) + RST
	case code >= 500:
		return RED + strconv.Itoa(code) + RST
	default:
		return GRY + strconv.Itoa(code) + RST
	}
}

func RT(ms int64) string {
	switch {
	case ms < 500:
		return GRN + fmt.Sprintf("%dms", ms) + RST
	case ms < 1500:
		return YEL + fmt.Sprintf("%dms", ms) + RST
	default:
		return RED + fmt.Sprintf("%dms", ms) + RST
	}
}

func Size(bytes int64) string {
	switch {
	case bytes < 1024:
		return GRY + fmt.Sprintf("%dB", bytes) + RST
	case bytes < 1024*1024:
		return GRY + fmt.Sprintf("%.1fKB", float64(bytes)/1024) + RST
	default:
		return GRY + fmt.Sprintf("%.1fMB", float64(bytes)/1024/1024) + RST
	}
}
