package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/neilschelly/vpcflowlogbeat/beater"
)

var Version = "0.0.3"
var Name = "vpcflowlogbeat"

func main() {
	if err := beat.Run(Name, Version, beater.New()); err != nil {
		os.Exit(1)
	}
}
