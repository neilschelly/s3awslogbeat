package main

import (
	"os"
	"net/http"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/neilschelly/s3awslogbeat/beater"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Version = "0.1.0"
var Name = "cloudtrailbeat"

func main() {
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9400", nil)

	if err := beat.Run(Name, Version, beater.New()); err != nil {
		os.Exit(1)
	}
}
