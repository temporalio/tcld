package utils_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/temporalio/tcld/utils"
)

func TestParseDuration(t *testing.T) {

	duration, err := utils.ParseDuration("99s")
	assert.NoError(t, err)
	assert.Equal(t, 99*time.Second, duration)

	duration, err = utils.ParseDuration("99m")
	assert.NoError(t, err)
	assert.Equal(t, 99*time.Minute, duration)

	duration, err = utils.ParseDuration("99m99s")
	assert.NoError(t, err)
	assert.Equal(t, 99*time.Minute+99*time.Second, duration)

	duration, err = utils.ParseDuration("99h")
	assert.NoError(t, err)
	assert.Equal(t, 99*time.Hour, duration)

	duration, err = utils.ParseDuration("99h99m99s")
	assert.NoError(t, err)
	assert.Equal(t, 99*time.Hour+99*time.Minute+99*time.Second, duration)

	duration, err = utils.ParseDuration("99d")
	assert.NoError(t, err)
	assert.Equal(t, 99*24*time.Hour, duration)

	duration, err = utils.ParseDuration("99d99h99m99s")
	assert.NoError(t, err)
	assert.Equal(t, 99*24*time.Hour+99*time.Hour+99*time.Minute+99*time.Second, duration)

	duration, err = utils.ParseDuration("99y")
	assert.NoError(t, err)
	assert.Equal(t, 99*365*24*time.Hour, duration)

	duration, err = utils.ParseDuration("99y99d99h99m99s")
	assert.NoError(t, err)
	assert.Equal(t, 99*365*24*time.Hour+99*24*time.Hour+99*time.Hour+99*time.Minute+99*time.Second, duration)

	duration, err = utils.ParseDuration("99.9y")
	assert.NoError(t, err)
	assert.Equal(t, 99.9*365*24*time.Hour, duration)

	// error scenarios
	_, err = utils.ParseDuration("y")
	assert.Error(t, err)

	_, err = utils.ParseDuration("12")
	assert.Error(t, err)

	_, err = utils.ParseDuration("99yy")
	assert.Error(t, err)

	_, err = utils.ParseDuration("99y45")
	assert.Error(t, err)

}
