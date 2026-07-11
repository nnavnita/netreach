FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/netreach ./cmd/netreach

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/netreach /netreach
ENTRYPOINT ["/netreach"]
