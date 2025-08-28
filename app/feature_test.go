package app

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestToggleFeature(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tcld-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	// Set the config directory flag to our temp directory
	originalConfigDir := ConfigDirFlag.Value
	ConfigDirFlag.Value = tmpDir
	defer func() {
		ConfigDirFlag.Value = originalConfigDir
	}()

	testFeatureName := supportFeatureFlags[0]

	err = toggleFeature(testFeatureName)
	if err != nil {
		t.Fatal(err)
	}

	featureFlags, err := getFeatureFlags()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, flag := range featureFlags {
		if flag.Name == testFeatureName {
			assert.Equal(t, true, flag.Value)
			found = true
			break
		}
	}
	assert.True(t, found)
}

func TestToggleFeatureAndRead(t *testing.T) {
	testFileName := uuid.NewString() + ".json"
	_, err := getFeatureFlagsFromConfigFile(testFileName)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(testFileName) // clean up

	// Toggle test feature on
	test_feature_flag := "test-feature"

	err = toggleFeatureSaveToPath(test_feature_flag, testFileName)
	if err != nil {
		t.Fatal(err)
	}

	// Read the file.
	jsonData, err := getFeatureFlagsFromConfigFile(testFileName)

	if err != nil {
		t.Fatal(err)
	}

	for _, feature := range jsonData {
		assert.Equal(t, test_feature_flag, feature.Name)
		assert.Equal(t, true, feature.Value)
	}

	// Toggle test feature off
	err = toggleFeatureSaveToPath(test_feature_flag, testFileName)
	if err != nil {
		t.Fatal(err)
	}

	// Read the file.
	jsonData, err = getFeatureFlagsFromConfigFile(testFileName)

	if err != nil {
		t.Fatal(err)
	}

	for _, feature := range jsonData {
		assert.Equal(t, test_feature_flag, feature.Name)
		assert.Equal(t, false, feature.Value)
	}
}
