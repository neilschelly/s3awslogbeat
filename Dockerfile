FROM golang:1.18

RUN mkdir -p /go/src/github.com/neilschelly/
RUN cd /go/src/github.com/neilschelly/ && git clone https://github.com/neilschelly/s3awslogbeat.git

WORKDIR /go/src/github.com/neilschelly/s3awslogbeat/
RUN git checkout origin/promexporter
RUN go mod vendor && go build

FROM debian:buster
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean
WORKDIR /
COPY --from=0 /go/src/github.com/neilschelly/s3awslogbeat/s3awslogbeat /usr/local/bin/s3awslogbeat

ENTRYPOINT ["/usr/local/bin/s3awslogbeat"]
CMD ["--help"]
