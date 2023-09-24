package database

import (
	"encoding/json"
	"errors"
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
}

// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	file, err := os.Open(path)
	defer file.Close()
	if errors.Is(err, fs.ErrNotExist) {
		file, err = os.Create(path)
		if err != nil {
			return nil, errors.New("Could not create DB file")
		}
	} else if err != nil {
		return nil, err
	}
	myDB := DB{path: path, mux: &sync.RWMutex{}}
	return &myDB, nil
}

// loadDB reads the database file into memory
func (db *DB) LoadDB() (DBStructure, error) {
	chirpsJSON := DBStructure{Chirps: map[int]Chirp{}}
	chirpsSlice := make([]Chirp, 0, 100)
	db.mux.Lock()
	chirpsBS, err := os.ReadFile(db.path)
	db.mux.Unlock()
	if err != nil {
		return chirpsJSON, err
	}
	err = json.Unmarshal(chirpsBS, &chirpsSlice)
	if err != nil {
		return chirpsJSON, err
	}
	sort.Slice(chirpsSlice, func(i, j int) bool { return chirpsSlice[i].Id < chirpsSlice[j].Id })
	for i, chirp := range chirpsSlice {
		chirpsJSON.Chirps[i] = chirp
	}
	return chirpsJSON, nil
}
