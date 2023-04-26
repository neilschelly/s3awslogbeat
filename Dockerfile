FROM golang:1.18

COPY ./ /go/src
WORKDIR /go/src/

RUN go mod vendor && go build -o s3awslogbeat

FROM debian:buster
RUN apt-get update && apt-get install -y ca-certificates && apt-get clean
WORKDIR /
COPY --from=0 /go/src/s3awslogbeat /usr/local/bin/s3awslogbeat

EXPOSE 9400/tcp
ENTRYPOINT ["/usr/local/bin/s3awslogbeat"]
CMD ["--help"]
