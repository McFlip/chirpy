package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Chirp struct {
	Id       int    `json:"id"`
	Body     string `json:"body"`
	AuthorId int    `json:"author_id"`
}

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps        map[int]Chirp        `json:"chirps"`
	Users         map[int]User         `json:"users"`
	RevokedTokens map[string]time.Time `json:"revoked_tokens"`
}

type User struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	IsChirpyRed bool   `json:"is_chirpy_red"`
}

var Chirp404 = errors.New("chirp not found")
var User404 = errors.New("user not found")

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	file, err := os.Open(db.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = os.WriteFile(db.path, []byte(`{"chirps":{}, "users":{}, "revoked_tokens":{}}`), 0666)
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
func (db *DB) CreateChirp(body string, author int) (Chirp, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in CreateChirp")
		return Chirp{}, err
	}
	myId := len(myDBStructure.Chirps) + 1
	myChirp := Chirp{AuthorId: author, Id: myId, Body: body}
	myDBStructure.Chirps[myId] = myChirp
	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in CreateChirp")
		return Chirp{}, err
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

// GetChirpById returns a chirp stuct
func (db *DB) GetChirpById(id int) (Chirp, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in GetChirps")
		return Chirp{}, err
	}

	myChirp, ok := myDBStructure.Chirps[id]
	if !ok {
		return Chirp{}, Chirp404
	}

	return myChirp, nil
}

func (db *DB) DelChirp(id int) error {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in DelChirp")
		return err
	}

	delete(myDBStructure.Chirps, id)

	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in DelChirp")
		return err
	}

	return nil
}

// Create a new user
func (db *DB) CreateUser(email string, pw []byte) (User, error) {
	_, err := db.GetUserByEmail(email)
	if err == nil {
		fmt.Println("ERROR user already exists")
		err = errors.New("user already exists")
		return User{Id: -1, Email: ""}, err
	} else if err.Error() != "user not found" {
		fmt.Println("ERROR checking if user already exists")
		return User{Id: -1, Email: ""}, err
	}
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in CreateUser")
		return User{Id: -1, Email: ""}, err
	}

	myId := len(myDBStructure.Users) + 1
	pw, err = bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("ERROR hashing pw in CreateUser")
		return User{Id: -1, Email: ""}, err
	}
	myUser := User{Id: myId, Email: email, Password: string(pw)}
	myDBStructure.Users[myId] = myUser
	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in CreateUser")
		return User{Id: -1, Email: ""}, err
	}

	return myUser, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in GetUserByEmail")
		return User{Id: -1, Email: ""}, err
	}
	for _, user := range myDBStructure.Users {
		if user.Email == email {
			return user, nil
		}
	}
	err = errors.New("user not found")
	return User{Id: -1, Email: ""}, err
}

func (db *DB) UpdateUser(id int, email string, password string) (User, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in UpdateUser")
		return User{Id: -1, Email: ""}, err
	}

	pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("ERROR hashing pw in CreateUser")
		return User{Id: -1, Email: ""}, err
	}

	updatedUser := User{Id: id, Password: string(pw), Email: email}
	myDBStructure.Users[id] = updatedUser

	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in UpdateUser")
		return User{Id: -1, Email: ""}, err
	}

	return updatedUser, nil
}

func (db *DB) UpgradeUser(id int) error {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in UpradeUser")
		return err
	}

	myUser, ok := myDBStructure.Users[id]
	if !ok {
		return User404
	}
	myUser.IsChirpyRed = true
	myDBStructure.Users[id] = myUser

	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in UpgradeUser")
		return err
	}

	return nil
}

func (db *DB) TokenIsRevoked(token string) (bool, error) {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in TokenIsRevoked")
		return false, err
	}

	_, status := myDBStructure.RevokedTokens[token]
	return status, nil
}

func (db *DB) RevokeToken(token string) error {
	myDBStructure, err := db.loadDB()
	if err != nil {
		fmt.Println("ERROR loading DB in RevokeToken")
		return err
	}

	myDBStructure.RevokedTokens[token] = time.Now()

	err = db.writeDB(myDBStructure)
	if err != nil {
		fmt.Println("ERROR writing to DB in RevokeToken")
		return err
	}
	return nil
}
