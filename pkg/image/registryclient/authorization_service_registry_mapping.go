package registryclient

import (
	"net/http"

	"github.com/docker/distribution/registry/client/auth"
)

type AuthorizationServiceRegistryMappingConsumer interface {
	AcceptAuthorizationServiceRegistryMapping(authorizationService, registry string)
}

type authorizationServiceHandler struct {
	credentialStore auth.CredentialStore
}

func (*authorizationServiceHandler) Scheme() string {
	return "bearer"
}

func (bh *authorizationServiceHandler) AuthorizeRequest(_ *http.Request, params map[string]string) error {
	if consumer, ok := bh.credentialStore.(AuthorizationServiceRegistryMappingConsumer); ok {
		// look for challenge params
		realm, ok := params["realm"] // authorizationService
		if !ok {
			return nil
		}
		service, ok := params["service"] // registry
		if !ok {
			return nil
		}
		consumer.AcceptAuthorizationServiceRegistryMapping(realm, service)
	}
	return nil
}
