package main

import (
	"os"

	cmd "github.com/jemurai/depcheck2off/cmd"
)

func main() {
	var depcheck string = os.Args[1]
	cmd.Convert(depcheck)
}
