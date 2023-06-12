package app

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFeatureFlagConfig(t *testing.T) {
	// Create a temporary file.
	tmpfile, err := ioutil.TempFile("", "example")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	// Write a JSON object to the temporary file.
	featureFlag := map[string]bool{"enable-export": true}
	b, err := json.Marshal(featureFlag)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpfile.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Call the function under test.
	result, err := GetFeatureFlagConfig(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Assert that the function correctly read the feature flag from the file.
	assert.Equal(t, featureFlag, result)
}
