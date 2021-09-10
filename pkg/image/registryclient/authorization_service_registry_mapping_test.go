package registryclient

import (
	"testing"
)

type consumerStore struct {
	BasicCredentials
	authorizationService, registry string
}

func (c *consumerStore) AcceptAuthorizationServiceRegistryMapping(authorizationService, registry string) {
	c.authorizationService = authorizationService
	c.registry = registry
}

func TestAuthorizationServiceHandler(t *testing.T) {
	credentialStore := &consumerStore{}
	handler := &authorizationServiceHandler{credentialStore}

	err := handler.AuthorizeRequest(nil, map[string]string{
		"realm":   "https://127.0.0.1:3000",
		"service": "https://127.0.0.1:5000",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if credentialStore.registry != "https://127.0.0.1:5000" {
		t.Fatalf("unexpected registry: %s", credentialStore.registry)
	}
	if credentialStore.authorizationService != "https://127.0.0.1:3000" {
		t.Fatalf("unexpected authorizationService: %s", credentialStore.authorizationService)
	}
}

func TestAuthorizationServiceHandlerLegacyStore(t *testing.T) {
	// BasicCredentials is not AuthorizationServiceRegistryMappingConsumer
	handler := &authorizationServiceHandler{credentialStore: NewBasicCredentials()}

	err := handler.AuthorizeRequest(nil, map[string]string{
		"realm":   "https://127.0.0.1:3000",
		"service": "https://127.0.0.1:5000",
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
