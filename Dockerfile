FROM golang:1.18

RUN git clone https://github.com/neilschelly/s3awslogbeat.git /go/src

WORKDIR /go/src/
RUN git checkout origin/promexporter
RUN go mod vendor && go build

FROM debian:buster
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean
WORKDIR /
COPY --from=0 /app/s3awslogbeat /usr/local/bin/s3awslogbeat

ENTRYPOINT ["/usr/local/bin/s3awslogbeat"]
CMD ["--help"]
