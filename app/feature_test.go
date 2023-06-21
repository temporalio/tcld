package app

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestToggleFeatureAndRead(t *testing.T) {
	testFileName := uuid.NewString() + ".json"
	_, err := getFeatureFlagConfig(testFileName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(testFileName) // clean up

	// Toggle test feature on
	test_feature_flag := "test-feature"

	err = toggle_feature_save_to_path(test_feature_flag, testFileName)
	if err != nil {
		t.Fatal(err)
	}

	// Read the file.
	jsonData, err := getFeatureFlagConfig(testFileName)

	if err != nil {
		t.Fatal(err)
	}

	for _, feature := range jsonData {
		assert.Equal(t, test_feature_flag, feature.Name)
		assert.Equal(t, true, feature.Value)
	}

	// Toggle test feature off
	err = toggle_feature_save_to_path(test_feature_flag, testFileName)
	if err != nil {
		t.Fatal(err)
	}

	// Read the file.
	jsonData, err = getFeatureFlagConfig(testFileName)

	if err != nil {
		t.Fatal(err)
	}

	for _, feature := range jsonData {
		assert.Equal(t, test_feature_flag, feature.Name)
		assert.Equal(t, false, feature.Value)
	}
}
