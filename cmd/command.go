package cmd

import (
	utils "github.com/jemurai/depcheck2off/utils"
)

func Convert(file string) {
	findings := utils.BuildFindingsFromOWASPDepCheckFile(file)
	utils.PrintFindings(findings)
}
