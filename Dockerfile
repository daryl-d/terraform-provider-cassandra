# Start by building the application.
FROM golang:1.10 as build

WORKDIR /go/src/github.com/daryl-d/terraform-provider-cassandra
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build

# Now copy it into our base image.
FROM scratch
USER 1000
COPY --from=build /go/src/github.com/daryl-d/terraform-provider-cassandra/terraform-provider-cassandra /terraform-provider-cassandra
ENTRYPOINT ["/terraform-provider-cassandra"]
