// backend server example project

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"srv/internal/database"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

type apiConfig struct {
	fileserverHits int
}
type errRes struct {
	Err string `json:"error"`
}

const maxChirpLen = 140
const genericErrMsg = "Something went wrong"

var forbiddenWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func main() {
	const filepathRoot = "."
	const port = "8080"
	const dbPath = "database.json"
	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Error connecting to DB: %s", err)
	}
	apiCfg := apiConfig{
		fileserverHits: 0,
	}

	mainRouter := chi.NewRouter()
	fsHandler := apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mainRouter.Handle("/app", fsHandler)
	mainRouter.Handle("/app/*", fsHandler)
	apiRouter := chi.NewRouter()

	apiRouter.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("OK"))
	})

	apiRouter.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		type parameters struct {
			Body string `json:"body"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding json body in POST chirps: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		validated, err := validateChirp(params.Body)
		if err != nil {
			respondWithErr(w, 400, err.Error())
			return
		}
		chirp, err := db.CreateChirp(validated)
		if err != nil {
			respondWithErr(w, 500, err.Error())
			return
		}
		respondWithJSON(w, 201, chirp)
	})

	apiRouter.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
		if err != nil {
			respondWithErr(w, 500, err.Error())
			return
		}
		respondWithJSON(w, 200, chirps)
	})

	apiRouter.Get("/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
		if err != nil {
			respondWithErr(w, 500, err.Error())
		}
		chirpId := chi.URLParam(r, "chirpId")
		chirpIdInt, err := strconv.Atoi(chirpId)
		if err != nil {
			respondWithErr(w, 400, err.Error())
			return
		}
		if chirpIdInt <= 0 || chirpIdInt > len(chirps) {
			respondWithErr(w, 404, "chirp not found")
			return
		}
		respondWithJSON(w, 200, chirps[chirpIdInt-1])
	})

	apiRouter.Post("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		type parameters struct {
			Email string `json:"email"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding json body in POST users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		user, err := db.CreateUser(params.Email)
		if err != nil {
			log.Printf("Error creating user in POST users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		respondWithJSON(w, 201, user)
	})

	adminRouter := chi.NewRouter()
	adminRouter.Get("/metrics", apiCfg.handlerMetrics)
	mainRouter.Mount("/api", apiRouter)
	mainRouter.Mount("/admin", adminRouter)
	corsMux := middlewareCors(mainRouter)
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: corsMux,
	}
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}

func respondWithErr(w http.ResponseWriter, code int, msg string) {
	resBody := errRes{
		Err: msg,
	}
	dat, err := json.Marshal(resBody)
	if err != nil {
		log.Printf("Error marshaling json body in respondWithErr: %s", err)
	}
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		respondWithErr(w, 500, genericErrMsg)
		return
	}
	w.WriteHeader(code)
	w.Write(dat)
}

func validateChirp(chirp string) (validatedChirp string, err error) {
	if len(chirp) > maxChirpLen {
		return "", errors.New("chirp is too long")
	}
	clean := ProfanityFilter(chirp)
	return clean, nil
}

func ProfanityFilter(msg string) string {
	words := strings.Split(msg, " ")
	for i, word := range words {
		for _, forbiddenWord := range forbiddenWords {
			if strings.ToLower(word) == forbiddenWord {
				words[i] = "****"
			}
		}
	}
	return strings.Join(words, " ")
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

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits)))
	fmt.Fprintf(w, "<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", cfg.fileserverHits)
}
