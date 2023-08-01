// backend server example project

package main

import (
	"log"
	"net/http"
)

func main() {
	staticServe := http.NewServeMux()
	staticServe.Handle("/", http.FileServer(http.Dir(".")))
	corsMux := middlewareCors(staticServe)
	srv := &http.Server{
		Addr: ":8080",
		Handler: corsMux,
	}
	log.Fatal(srv.ListenAndServe())
}

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}