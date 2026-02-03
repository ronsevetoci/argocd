FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN go build -o app

FROM gcr.io/distroless/base-debian12
COPY --from=build /src/app /app
EXPOSE 8080
CMD ["/app"]
