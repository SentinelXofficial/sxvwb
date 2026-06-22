package banner

import (
	"fmt"

	"github.com/SentinelXofficial/sxvwb/internal/color"
	"github.com/SentinelXofficial/sxvwb/internal/updater"
	"github.com/SentinelXofficial/sxvwb/internal/version"
)

func Print() {
	fmt.Println()
	fmt.Print(color.CYN + `  _______________   __________  _  _______` + color.RST + "\n")
	fmt.Print(color.CYN + ` / ___/_  __/ __ \ | |  / / __ )/ |/ / ___/` + color.RST + "\n")
	fmt.Print(color.CYN + ` \__ \ / / / / / / | | / / __  /    / /__` + color.RST + "\n")
	fmt.Print(color.CYN + ` ___/ // / / /_/ /  | |/ / /_/ /|  |\___ \` + color.RST + "\n")
	fmt.Print(color.CYN + `/____//_/  \___\_\  |___/_____/_/|_/____/` + color.RST + "\n")
	fmt.Println()
	fmt.Println(color.GRY + "  SentinelX VWB" + color.RST + color.GRY + color.DIM + " — Web Vulnerability Scanner" + color.RST)
	fmt.Println(color.GRY + color.DIM + "  Author : WildanDev" + color.RST)
	fmt.Println()
	printRestrictionNotice()
	fmt.Println()
	printVersionInfo()
}

func printRestrictionNotice() {
	fmt.Println(color.YEL + "  ⚠ RESTRICTED DOMAINS — Scanning is NOT allowed on:" + color.RST)
	fmt.Println(color.RED + "  *.id TLDs (co.id, go.id, ac.id, sch.id, mil.id, or.id," + color.RST)
	fmt.Println(color.RED + "           net.id, web.id, my.id, biz.id, desa.id, ponpes.id)" + color.RST)
	fmt.Println(color.RED + "  github.com" + color.RST)
	fmt.Println()
}

func printVersionInfo() {
	latest, err := updater.FetchLatest()
	if err != nil {
		// silently skip if can't reach github
		return
	}
	if latest != version.Current {
		fmt.Printf(
			color.GRY+"  [INF] Current sxvwb version: "+color.BOLD+"%s"+color.RST+color.YEL+" (outdated, latest: %s)"+color.RST+"\n\n",
			version.Current, latest,
		)
	} else {
		fmt.Printf(
			color.GRY+"  [INF] Current sxvwb version: "+color.BOLD+"%s"+color.RST+color.GRN+" (latest)"+color.RST+"\n\n",
			version.Current,
		)
	}
}
