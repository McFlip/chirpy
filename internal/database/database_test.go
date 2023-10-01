package database

import (
	"os"
	"regexp"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func Test_createNewFile(t *testing.T) {
	const path string = "noExist.json"
	defer os.Remove(path)
	testDB, err := NewDB(path)
	if err != nil {
		t.Error(err)
	}
	if testDB.path != path {
		t.Errorf("Expected %q but received %q", path, testDB.path)
	}
	noExistBS, err := os.ReadFile(testDB.path)
	if err != nil {
		t.Error(err)
	}
	if len(noExistBS) != 25 {
		t.Errorf("Expected length of file to be 25 but it's %d", len(noExistBS))
	}
}

func Test_loadDB(t *testing.T) {
	expected := Chirp{Body: "I had something interesting for breakfast",
		Id: 1}
	testDB, err := NewDB("fixture.json")
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	testDBStruct, err := testDB.loadDB()
	if err != nil {
		t.Errorf("Failed to unmarshal DB: %s", err)
	}
	if testDBStruct.Chirps[1] != expected {
		t.Errorf("Expected 0th Chirp to be %#v but received %#v", expected, testDBStruct)
	}
}

func Test_writeDB(t *testing.T) {
	const path string = "writeTest.json"
	defer os.Remove(path)
	testDB, err := NewDB(path)
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	testDBStruct := DBStructure{
		Chirps: map[int]Chirp{1: {Id: 1, Body: "First Chirp!"}, 2: {Id: 2, Body: "Second Chirp."}},
	}

	err = testDB.writeDB(testDBStruct)
	if err != nil {
		t.Errorf("Failed to write to DB: %s", err)
	}

	output, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("Failed to read to DB: %s", err)
	}
	expectedChirps := []string{"First Chirp", "Second Chirp"}
	for _, expectedChirp := range expectedChirps {
		match, err := regexp.Match(expectedChirp, output)
		if err != nil {
			t.Errorf("regex failed: %s", err)
		}
		if !match {
			t.Errorf("%s not found in output:\n%s", expectedChirp, output)
		}
	}
}

func Test_CreateChirp(t *testing.T) {
	const path string = "createDB.json"
	defer os.Remove(path)
	testBody := []string{"First Chirp", "Second Chirp"}
	testDB, err := NewDB(path)
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}

	for i, body := range testBody {
		testChirp, err := testDB.CreateChirp(body)
		if err != nil {
			t.Errorf("Failed to create test chirp: %s", err)
		}
		if testChirp.Id != i+1 {
			t.Errorf("Expected ID of %d for testChirp but got %d", i+1, testChirp.Id)
		}
		if testChirp.Body != body {
			t.Errorf("Expected testChirp body to be %q, but got %q", body, testChirp.Body)
		}
	}
}

func Test_GetChirps(t *testing.T) {
	testDB, err := NewDB("fixture.json")
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	chirps, err := testDB.GetChirps()
	if err != nil {
		t.Errorf("Failed to get chirps: %s", err)
	}

	if len(chirps) != 3 {
		t.Errorf("Expected 3 chirps but got %d", len(chirps))
	}
	const expectedChirp string = "What about second breakfast?"
	if chirps[1].Body != expectedChirp {
		t.Errorf("Expected 2nd chirp to be %q, but got %s", expectedChirp, chirps[2].Body)
	}
}

func Test_CreateUser(t *testing.T) {
	const path = "users.json"
	defer os.Remove(path)
	testDB, err := NewDB(path)
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	const userEmail = "myuser@local"
	const userPassword = "P@ssW0rd"
	expected := User{Id: 1, Email: userEmail}

	actual, err := testDB.CreateUser(userEmail, []byte(userPassword))
	if err != nil {
		t.Errorf("Failed to create test user: %s", err.Error())
	}

	if actual.Id != expected.Id || actual.Email != expected.Email {
		t.Errorf("Expected User %v, but got %v", expected, actual)
	}
	err = bcrypt.CompareHashAndPassword([]byte(actual.Password), []byte(userPassword))
	if err != nil {
		t.Errorf("Password comparison failed: %s", err.Error())
	}
}

func Test_UpdateUser(t *testing.T) {
	const path = "updateUsers.json"
	defer os.Remove(path)
	testDB, err := NewDB(path)
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	testDB.CreateUser("first@test", []byte("firstPW"))
	expected := User{
		Id:       1,
		Email:    "newemail@test",
		Password: "newpw",
	}

	actual, err := testDB.UpdateUser(1, "newemail@test", "newpw")
	if err != nil {
		t.Errorf("Failed to update user: %s", err)
	}

	if actual.Email != expected.Email {
		t.Errorf("Expected updated user email to be %v, but got %v", expected, actual)
	}

	err = bcrypt.CompareHashAndPassword([]byte(actual.Password), []byte(expected.Password))
	if err != nil {
		t.Errorf("Password comparison failed: %s", err.Error())
	}

}
