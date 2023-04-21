BEATNAME=cloudtrailbeat
BEAT_DIR=github.com/neilschelly/s3awslogbeat
#ES_BEATS=/go/pkg/mod/github.com/elastic/beats@v5.0.0-alpha1.0.20160419145706-a0f543d88691+incompatible/
#GOPACKAGES=$(shell glide novendor)
SYSTEM_TESTS=false

# Only crosscompile for linux because other OS'es use cgo.
#GOX_OS=linux darwin windows solaris freebsd netbsd openbsd
GOX_OS=linux

#include $(ES_BEATS)/libbeat/scripts/Makefile

# Specifying output command name
.PHONY: build
build: $(GOFILES)
	go build -o $(BEATNAME)
