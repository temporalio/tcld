package app

import (
	"github.com/stretchr/testify/assert"
	"github.com/temporalio/tcld/protogen/api/namespace/v1"
	"testing"
)

func TestParseAndConvertCodecServerSuccess(t *testing.T) {
	successJsonStr := "{ \"Endpoint\": \"https://test-endpoint.com\", \"PassAccessToken\": true, \"IncludeCredentials\": false }"
	spec, err := parseAndConvertCodecServer(successJsonStr)
	assert.NoError(t, err)
	assert.Equal(t, &namespace.CodecServerPropertySpec{
		Endpoint:           "https://test-endpoint.com",
		PassAccessToken:    true,
		IncludeCredentials: false}, spec)
}

func TestParseAndConvertCodecServerFailure(t *testing.T) {
	invalidJsonStr := "{ \"Endpoint\": \"https://test-endpoint.com\", \"PassToken\": true \"IncludeCredentials\": false }"
	spec, err := parseAndConvertCodecServer(invalidJsonStr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid character '\"' after object")
	assert.Equal(t, &namespace.CodecServerPropertySpec{}, spec)

	emptyEndpointStr := "{ \"Endpoint\": \"\", \"PassToken\": true, \"IncludeCredentials\": false }"
	spec, err = parseAndConvertCodecServer(emptyEndpointStr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "field Endpoint has to be specified")
	assert.Equal(t, &namespace.CodecServerPropertySpec{}, spec)

	nonHttpsEndpointStr := "{ \"Endpoint\": \"http://test-endpoint.com\", \"PassToken\": true, \"IncludeCredentials\": false }"
	spec, err = parseAndConvertCodecServer(nonHttpsEndpointStr)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "field Endpoint has to use https")
	assert.Equal(t, &namespace.CodecServerPropertySpec{}, spec)
}
