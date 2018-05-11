package oauth

// ClientAuthorizationName creates the computed name for a given username, clientName tuple
// This cannot change or client authorizations will be have unpredictably
func ClientAuthorizationName(userName, clientName string) string {
	return userName + ":" + clientName
}
