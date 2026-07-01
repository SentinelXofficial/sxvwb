package banner

import (
	"fmt"
	"os"

	"github.com/SentinelXofficial/sxvwb/internal/color"
	"github.com/SentinelXofficial/sxvwb/internal/updater"
	"github.com/SentinelXofficial/sxvwb/internal/version"
)

func Print() {
	fmt.Println()
	fmt.Print(color.CYN + `   _____            __  _            __  _  __` + color.RST + "\n")
	fmt.Print(color.CYN + `  / ___/___  ____  / /_(_)___  ___  / / | |/ /` + color.RST + "\n")
	fmt.Print(color.CYN + `  \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  |   /` + color.RST + "\n")
	fmt.Print(color.CYN + ` ___/ /  __/ / / / /_/ / / / /  __/ /___/   |` + color.RST + "\n")
	fmt.Print(color.CYN + `/____/\___/_/ /_/\__/_/_/ /_/\___/_____/_/|_|` + color.RST + "\n")
	fmt.Println()
	fmt.Println(color.GRY + "  SentinelX VWB" + color.RST + color.GRY + color.DIM + " — Web Vulnerability Scanner" + color.RST)
	fmt.Println(color.GRY + color.DIM + "  Author : WildanDev" + color.RST)
	fmt.Println()
	printRestrictionNotice()
	fmt.Println()
	printLicenseStatus()
	printVersionInfo()
}

func printLicenseStatus() {
	key := os.Getenv("SXVWB_LICENSE")
	if key == "" {
		fmt.Println(color.YEL + "  [!] No license key set. Get one at https://api.sentinelx.me/register" + color.RST)
		fmt.Println(color.YEL + "  [!] Set with: export SXVWB_LICENSE=your-key" + color.RST)
	} else {
		short := key[:14] + "..." + key[len(key)-8:]
		fmt.Println(color.GRN + "  [✓] License: " + short + color.RST)
	}
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
