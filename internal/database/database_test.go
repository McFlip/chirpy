package database

import (
	"fmt"
	"os"
	"testing"
)

func Test_createNewFile(t *testing.T) {
	const path string = "noExist.json"
	defer os.Remove(path)
	err := os.Remove(path)
	if err != nil {
		fmt.Print(err)
	}
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
	if len(noExistBS) != 0 {
		t.Errorf("Expected length of file to be 0 but it's %d", len(noExistBS))
	}
}

func Test_loadDB(t *testing.T) {
	expected := Chirp{Body: "I had something interesting for breakfast",
		Id: 1}
	testDB, err := NewDB("fixture.json")
	if err != nil {
		t.Errorf("Failed to create test DB: %s", err)
	}
	testDBStruct, err := testDB.LoadDB()
	if err != nil {
		t.Errorf("Failed to unmarshal DB: %s", err)
	}
	if testDBStruct.Chirps[0] != expected {
		t.Errorf("Expected 0th Chirp to be %#v but received %#v", expected, testDBStruct)
	}
}
