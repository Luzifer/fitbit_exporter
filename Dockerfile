FROM alpine

ENV GOPATH /go/src/github.com/Luzifer/fitbit_exporter/Godeps/_workspace:/go
EXPOSE 3000

ADD ./ /go/src/github.com/Luzifer/fitbit_exporter
WORKDIR /go/src/github.com/Luzifer/fitbit_exporter

RUN apk --update add go ca-certificates \
 && go install

ENTRYPOINT ["/go/bin/fitbit_exporter"]
CMD ["--"]
