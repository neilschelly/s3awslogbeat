package s3awslogbeat

import (
	"os"

	"github.com/elastic/beats/libbeat/beat"
	"s3awslogbeat/beater"
)

var Version = "0.1.0"
var Name = "s3awslogbeat"

func main() {
	if err := beat.Run(Name, Version, beater.New()); err != nil {
		os.Exit(1)
	}
}
