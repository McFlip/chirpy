// backend server example project

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"srv/internal/database"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type apiConfig struct {
	fileserverHits int
	jwtSecret      string
}
type errRes struct {
	Err string `json:"error"`
}

type userRes struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

type loginRes struct {
	userRes
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"token"`
}

type refreshRes struct {
	AccessToken string `json:"token"`
}

const maxChirpLen = 140
const genericErrMsg = "Something went wrong"
const loginErrMsg = "Incorrect Username or Password"
const refreshTimeout = time.Hour * 24 * 60
const refreshIssuer = "chirpy-refresh"
const accessTimeout = time.Hour
const accessIssuer = "chirpy-access"

var forbiddenWords = []string{
	"kerfuffle",
	"sharbert",
	"fornax",
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	jwtSecret := os.Getenv("JWT_SECRET")

	const filepathRoot = "."
	const port = "8080"
	const dbPath = "database.json"
	db, err := database.NewDB(dbPath)
	if err != nil {
		log.Fatalf("Error connecting to DB: %s", err)
	}
	apiCfg := apiConfig{
		fileserverHits: 0,
		jwtSecret:      jwtSecret,
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
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding json body in POST users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		user, err := db.CreateUser(params.Email, []byte(params.Password))
		if err != nil {
			log.Printf("Error creating user in POST users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		res := userRes{
			Id:    user.Id,
			Email: user.Email,
		}
		respondWithJSON(w, 201, res)
	})

	apiRouter.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding json body in POST login: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		user, err := db.GetUserByEmail(params.Email)
		if err != nil {
			log.Printf("Error looking up user in POST login: %s", err)
			respondWithErr(w, 401, loginErrMsg)
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(params.Password))
		if err != nil {
			log.Printf("Error looking up user in POST login: %s", err)
			respondWithErr(w, 401, loginErrMsg)
			return
		}

		mySigningKey := []byte(jwtSecret)
		refreshToken, err := makeJWT(refreshIssuer, refreshTimeout, user.Id, mySigningKey)
		if err != nil {
			log.Printf("Error signing JWT in POST login: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		accessToken, err := makeJWT(accessIssuer, accessTimeout, user.Id, mySigningKey)
		if err != nil {
			log.Printf("Error signing JWT in POST login: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		res := loginRes{
			userRes: userRes{
				Id:    user.Id,
				Email: user.Email,
			},
			RefreshToken: refreshToken,
			AccessToken:  accessToken,
		}
		respondWithJSON(w, 200, res)
	})

	apiRouter.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		type parameters struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding json body in PUT users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		claims := jwt.RegisteredClaims{}
		JWT, err := jwt.ParseWithClaims(bearer, &claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			log.Printf("Error parsing claims: %s", err)
			respondWithErr(w, 401, loginErrMsg)
			return
		}
		iss, err := JWT.Claims.GetIssuer()
		if err != nil {
			log.Printf("Error getting Issuer from JWT claim in PUT users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		if iss != accessIssuer {
			log.Printf("Incorrect token used in PUT users: %s", iss)
			respondWithErr(w, 401, loginErrMsg)
			return
		}
		subj, err := JWT.Claims.GetSubject()
		if err != nil {
			log.Printf("Error getting Subject from JWT claim in PUT users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		// log.Printf("Claimed ID is %s", subj)
		subjInt, err := strconv.Atoi(subj)
		if err != nil {
			log.Printf("Error casting JWT subj to int in PUT users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		updatedUser, err := db.UpdateUser(subjInt, params.Email, params.Password)
		if err != nil {
			log.Printf("Error updating user in DB in PUT users: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		res := userRes{
			Id:    updatedUser.Id,
			Email: updatedUser.Email,
		}
		respondWithJSON(w, 200, res)
	})

	apiRouter.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		claims := jwt.RegisteredClaims{}
		myJWT, err := jwt.ParseWithClaims(bearer, &claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			log.Printf("Error parsing claims: %s", err)
			respondWithErr(w, 401, loginErrMsg)
			return
		}
		iss, err := myJWT.Claims.GetIssuer()
		if err != nil {
			log.Printf("Error getting Issuer from JWT claim in POST refresh: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		if iss != refreshIssuer {
			log.Printf("Incorrect token used in POST refresh: %s", iss)
			respondWithErr(w, 401, loginErrMsg)
			return
		}

		status, err := db.TokenIsRevoked(myJWT.Raw)
		if status == true {
			log.Printf("Revoked token:%s", myJWT.Raw)
		}

		subj, err := myJWT.Claims.GetSubject()
		if err != nil {
			log.Printf("Error getting Subject from JWT claim in POST refresh: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}
		subjInt, err := strconv.Atoi(subj)
		if err != nil {
			log.Printf("Error casting JWT subj to int in POST refresh: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		tok, err := makeJWT(accessIssuer, accessTimeout, subjInt, []byte(jwtSecret))
		if err != nil {
			log.Printf("Error creating access token in POST refresh: %s", err)
			respondWithErr(w, 500, genericErrMsg)
			return
		}

		respondWithJSON(w, 200, refreshRes{AccessToken: tok})
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

func makeJWT(issuer string, timout time.Duration, userId int, secret []byte) (string, error) {
	claims := &jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  &jwt.NumericDate{Time: time.Now()},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 60)),
		Subject:   fmt.Sprintf("%d", userId),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return ss, nil
}
