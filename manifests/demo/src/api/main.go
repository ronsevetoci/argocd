package main

import (
  "net/http"
)

func main() {
  http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
    w.Write([]byte("ok"))
  })
  http.ListenAndServe(":8080", nil)
}
