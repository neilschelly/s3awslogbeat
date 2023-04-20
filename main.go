package main

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/neilschelly/s3awslogbeat/beater"
)

var Version = "0.0.3"
var Name = "cloudtrailbeat"

func main() {
	if err := beat.Run(Name, Version, beater.New()); err != nil {
		os.Exit(1)
	}
}
