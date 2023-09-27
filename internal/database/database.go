package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
)

type Chirp struct {
	Id   int    `json:"id"`
	Body string `json:"body"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type User struct {
	Id    int    `json:"id"`
	Email string `json:"email"`
}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	file, err := os.Open(db.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = os.WriteFile(db.path, []byte(`{"chirps":{}, "users":{}}`), 0666)
			if err != nil {
				return errors.New("could not create DB file")
			}
		} else {
			return err
		}
	}
	defer file.Close()
	return nil
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	myDB := DB{path: path, mux: &sync.RWMutex{}}
	err := myDB.ensureDB()
	if err != nil {
		return nil, err
	}
	return &myDB, nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	chirpsJSON := DBStructure{Chirps: map[int]Chirp{}}
	db.mux.Lock()
	chirpsBS, err := os.ReadFile(db.path)
	db.mux.Unlock()
	if err != nil {
		return chirpsJSON, err
	}
	err = json.Unmarshal(chirpsBS, &chirpsJSON)
	if err != nil {
		return chirpsJSON, err
	}
	return chirpsJSON, nil
}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	chirpsJSON, err := json.Marshal(dbStructure)
	if err != nil {
		return err
	}
	db.mux.Lock()
	err = os.WriteFile(db.path, chirpsJSON, os.FileMode(0666))
	db.mux.Unlock()
	if err != nil {
		return err
	}
	return nil
}

// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string) (Chirp, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in CreateChirp")
		return Chirp{Id: -1, Body: ""}, err
	}
	myId := len(myDBStructure.Chirps) + 1
	myChirp := Chirp{Id: myId, Body: body}
	myDBStructure.Chirps[myId] = myChirp
	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in CreateChirp")
		return Chirp{Id: -1, Body: ""}, err
	}
	return myChirp, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	chirps := []Chirp{}
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in GetChirps")
		return chirps, err
	}
	for _, c := range myDBStructure.Chirps {
		chirps = append(chirps, c)
	}
	sort.Slice(chirps, func(i, j int) bool { return chirps[i].Id < chirps[j].Id })
	return chirps, nil
}

// Create a new user
func (db *DB) CreateUser(email string) (User, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in CreateUser")
	}

	myId := len(myDBStructure.Users) + 1
	myUser := User{Id: myId, Email: email}
	myDBStructure.Users[myId] = myUser
	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in CreateUser")
		return User{Id: -1, Email: ""}, err
	}

	return myUser, nil
}
