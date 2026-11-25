package tokenrequest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openshift/osincli"

	"k8s.io/apimachinery/pkg/util/diff"
	restclient "k8s.io/client-go/rest"

	"github.com/openshift/library-go/pkg/oauth/oauthdiscovery"
	"github.com/openshift/library-go/pkg/oauth/tokenrequest/challengehandlers"
)

type testPasswordPrompter struct{}

func (*testPasswordPrompter) PromptForPassword(r io.Reader, w io.Writer, format string, a ...interface{}) string {
	fmt.Fprintf(w, format, a...)
	var result string
	fmt.Fscan(r, &result)
	return result
}

func TestRequestToken(t *testing.T) {
	type req struct {
		authorization string
		method        string
		path          string
	}
	type resp struct {
		status          int
		location        string
		wwwAuthenticate []string
	}

	type requestResponse struct {
		expectedRequest req
		serverResponse  resp
	}

	var verifyReleased func(test string, handler challengehandlers.ChallengeHandler)
	verifyReleased = func(test string, handler challengehandlers.ChallengeHandler) {
		switch handler := handler.(type) {
		case *challengehandlers.MultiHandler:
			for _, subhandler := range handler.Handlers() {
				verifyReleased(test, subhandler)
			}
		case *challengehandlers.BasicChallengeHandler:
			// we don't care
		default:
			t.Errorf("%s: unrecognized handler: %#v", test, handler)
		}
	}

	initialRequest := req{}

	initialHead := req{"", http.MethodHead, "/"}
	initialHeadResp := resp{http.StatusInternalServerError, "", nil} // value of status is ignored

	basicChallenge1 := resp{401, "", []string{"Basic realm=foo"}}
	basicRequest1 := req{"Basic bXl1c2VyOm15cGFzc3dvcmQ=", "", ""} // base64("myuser:mypassword")
	basicRequestOnlyUsername := req{"Basic bXl1c2VyOg==", "", ""}  // base64("myuser:")
	basicChallenge2 := resp{401, "", []string{"Basic realm=seriously...foo"}}

	negotiateChallenge1 := resp{401, "", []string{"Negotiate"}}

	doubleChallenge := resp{401, "", []string{"Negotiate", "Basic realm=foo"}}

	successfulToken := "12345"
	successfulLocation := fmt.Sprintf("/#access_token=%s", successfulToken)
	success := resp{302, successfulLocation, nil}
	// successWithNegotiate := resp{302, successfulLocation, []string{"Negotiate Y2hhbGxlbmdlMg=="}}

	testcases := map[string]struct {
		Handler       challengehandlers.ChallengeHandler
		Requests      []requestResponse
		ExpectedToken string
		ExpectedError string
	}{
		// Defaulting basic handler
		"defaulted basic handler, no challenge, success": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic challenge, success": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic+negotiate challenge, success": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"defaulted basic handler, basic challenge, failure": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequest1, basicChallenge2},
			},
			ExpectedError: "challenger chose not to retry the request",
		},
		"defaulted basic handler, negotiate challenge, failure": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser", Password: "mypassword"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},
		"no username, basic challenge, failure": {
			Handler: &challengehandlers.BasicChallengeHandler{},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
			},
			ExpectedError: BasicAuthNoUsernameMessage,
		},
		"failing basic handler, basic challenge, failure": {
			Handler: &challengehandlers.BasicChallengeHandler{Username: "myuser"},
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequestOnlyUsername, basicChallenge1},
			},
			ExpectedError: "challenger chose not to retry the request",
		},

		// Prompting basic handler
		"prompting basic handler, no challenge, success": {
			Handler: challengehandlers.NewBasicChallengeHandler("", "", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, success": {
			Handler: challengehandlers.NewBasicChallengeHandler("", "", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic+negotiate challenge, success": {
			Handler: challengehandlers.NewBasicChallengeHandler("", "", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, failure": {
			Handler: challengehandlers.NewBasicChallengeHandler("", "", nil, nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequestOnlyUsername, basicChallenge2},
			},
			ExpectedError: "challenger chose not to retry the request",
		},
		"prompting basic handler, negotiate challenge, failure": {
			Handler: challengehandlers.NewBasicChallengeHandler("", "", bytes.NewBufferString("myuser\nmypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, negotiateChallenge1},
			},
			ExpectedError: "unhandled challenge",
		},
	}

	for k, tc := range testcases {
		t.Run(k, func(t *testing.T) {
			i := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				defer func() {
					if err := recover(); err != nil {
						t.Errorf("test %s panicked: %v", k, err)
					}
				}()

				if i >= len(tc.Requests) {
					t.Errorf("%s: %d: more requests received than expected: %#v", k, i, req)
					return
				}
				rr := tc.Requests[i]
				i++

				method := rr.expectedRequest.method
				if len(method) == 0 {
					method = http.MethodGet
				}
				if req.Method != method {
					t.Errorf("%s: %d: Expected %s, got %s", k, i, method, req.Method)
					return
				}

				path := rr.expectedRequest.path
				if len(path) == 0 {
					path = "/oauth/authorize"
				}
				if req.URL.Path != path {
					t.Errorf("%s: %d: Expected %s, got %s", k, i, path, req.URL.Path)
					return
				}

				if e, a := rr.expectedRequest.authorization, req.Header.Get("Authorization"); e != a {
					t.Errorf("%s: %d: expected 'Authorization: %s', got 'Authorization: %s'", k, i, e, a)
					return
				}

				if len(rr.serverResponse.location) > 0 {
					w.Header().Add("Location", rr.serverResponse.location)
				}
				for _, v := range rr.serverResponse.wwwAuthenticate {
					w.Header().Add("WWW-Authenticate", v)
				}
				w.WriteHeader(rr.serverResponse.status)
			}))
			defer s.Close()

			opts := &RequestTokenOptions{
				ClientConfig: &restclient.Config{
					Host: s.URL,
					TLSClientConfig: restclient.TLSClientConfig{
						CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}),
					},
				},
				Handler: tc.Handler,
				OsinConfig: &osincli.ClientConfig{
					ClientId:     openShiftCLIClientID,
					AuthorizeUrl: oauthdiscovery.OpenShiftOAuthAuthorizeURL(s.URL),
					TokenUrl:     oauthdiscovery.OpenShiftOAuthTokenURL(s.URL),
					RedirectUrl:  oauthdiscovery.OpenShiftOAuthTokenImplicitURL(s.URL),
				},
				Issuer:    s.URL,
				TokenFlow: true,
			}
			token, err := opts.requestTokenWithChallengeHandlers()
			if token != tc.ExpectedToken {
				t.Errorf("%s: expected token '%s', got '%s'", k, tc.ExpectedToken, token)
			}
			errStr := ""
			if err != nil {
				errStr = err.Error()
			}
			if errStr != tc.ExpectedError {
				t.Errorf("%s: expected error '%s', got '%s'", k, tc.ExpectedError, errStr)
			}
			if i != len(tc.Requests) {
				t.Errorf("%s: expected %d requests, saw %d", k, len(tc.Requests), i)
			}
			verifyReleased(k, tc.Handler)
		})
	}
}

func TestSetDefaultOsinConfig(t *testing.T) {
	noHostChange := func(host string) string { return host }
	loopbackRedirectUrl := "http://127.0.0.1:12345/callback"
	for _, tc := range []struct {
		name        string
		metadata    *oauthdiscovery.OauthAuthorizationServerMetadata
		hostWrapper func(host string) (newHost string)
		tokenFlow   bool
		clientName  string
		redirectUrl *string

		expectPKCE     bool
		expectedConfig *osincli.ClientConfig
	}{
		{
			name: "code with PKCE support from server",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "code without PKCE support from server",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"someotherstuff"},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "token with PKCE support from server",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   true,
			clientName:  openShiftCLIClientID,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "code with PKCE support from server, but wrong case",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"s256"}, // we are case sensitive so this is not valid
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "token without PKCE support from server",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{"random"},
			},
			hostWrapper: noHostChange,
			tokenFlow:   true,
			clientName:  openShiftCLIClientID,

			expectPKCE: false,
			expectedConfig: &osincli.ClientConfig{
				ClientId:     openShiftCLIClientID,
				AuthorizeUrl: "b",
				TokenUrl:     "c",
				RedirectUrl:  "a/oauth/token/implicit",
			},
		},
		{
			name: "host with extra slashes",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: func(host string) string { return host + "/////" },
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "issuer with extra slashes",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a/////",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         "a/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "code with PKCE support from server, more complex JSON",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "arandomissuerthatisfun123!!!///",
				AuthorizationEndpoint:         "44authzisanawesomeendpoint",
				TokenEndpoint:                 "&&buttokenendpointisprettygoodtoo",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIClientID,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIClientID,
				AuthorizeUrl:        "44authzisanawesomeendpoint",
				TokenUrl:            "&&buttokenendpointisprettygoodtoo",
				RedirectUrl:         "arandomissuerthatisfun123!!!/oauth/token/implicit",
				CodeChallengeMethod: pkce_s256,
			},
		},
		{
			name: "code with PKCE support from server, client with loopback redirect URL",
			metadata: &oauthdiscovery.OauthAuthorizationServerMetadata{
				Issuer:                        "a",
				AuthorizationEndpoint:         "b",
				TokenEndpoint:                 "c",
				CodeChallengeMethodsSupported: []string{pkce_s256},
			},
			hostWrapper: noHostChange,
			tokenFlow:   false,
			clientName:  openShiftCLIBrowserClientID,
			redirectUrl: &loopbackRedirectUrl,

			expectPKCE: true,
			expectedConfig: &osincli.ClientConfig{
				ClientId:            openShiftCLIBrowserClientID,
				AuthorizeUrl:        "b",
				TokenUrl:            "c",
				RedirectUrl:         loopbackRedirectUrl,
				CodeChallengeMethod: pkce_s256,
			},
		},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != "GET" {
				t.Errorf("%s: Expected GET, got %s", tc.name, req.Method)
				return
			}
			if req.URL.Path != oauthMetadataEndpoint {
				t.Errorf("%s: Expected metadata endpoint, got %s", tc.name, req.URL.Path)
				return
			}
			data, err := json.Marshal(tc.metadata)
			if err != nil {
				t.Errorf("%s: unexpected json error: %v", tc.name, err)
				return
			}
			w.Write(data)
		}))
		defer s.Close()

		opts := &RequestTokenOptions{
			ClientConfig: &restclient.Config{Host: tc.hostWrapper(s.URL)},
			TokenFlow:    tc.tokenFlow,
		}
		if err := opts.SetDefaultOsinConfig(tc.clientName, tc.redirectUrl); err != nil {
			t.Errorf("%s: unexpected SetDefaultOsinConfig error: %v", tc.name, err)
			continue
		}

		// check PKCE data
		if tc.expectPKCE {
			if len(opts.OsinConfig.CodeChallenge) == 0 || len(opts.OsinConfig.CodeChallengeMethod) == 0 || len(opts.OsinConfig.CodeVerifier) == 0 {
				t.Errorf("%s: did not set PKCE", tc.name)
				continue
			}
		} else {
			if len(opts.OsinConfig.CodeChallenge) != 0 || len(opts.OsinConfig.CodeChallengeMethod) != 0 || len(opts.OsinConfig.CodeVerifier) != 0 {
				t.Errorf("%s: incorrectly set PKCE", tc.name)
				continue
			}
		}

		// blindly unset random PKCE data since we already checked for it
		opts.OsinConfig.CodeChallenge = ""
		opts.OsinConfig.CodeVerifier = ""

		// compare the configs to see if they match
		if !reflect.DeepEqual(*tc.expectedConfig, *opts.OsinConfig) {
			t.Errorf("%s: expected osin config does not match, %s", tc.name, diff.Diff(*tc.expectedConfig, *opts.OsinConfig))
		}
	}
}

func TestRequestToken_BrowserFlow(t *testing.T) {
	type expectedRequest struct {
		method     string
		path       string
		response   string
		parameters map[string][]string
	}

	for _, tc := range []struct {
		name               string
		requests           []expectedRequest
		expectedToken      string
		codeChallenge      string
		codeVerifier       string
		expectError        string
		callbackParameters url.Values
	}{
		{
			name: "successful token retrieval",
			requests: []expectedRequest{
				{
					method: http.MethodHead, path: "/",
				},
				{
					method: http.MethodGet,
					path:   "/oauth/authorize",
					parameters: map[string][]string{
						"client_id":             {openShiftCLIBrowserClientID},
						"code_challenge":        {"code-challenge-encrypted"},
						"code_challenge_method": {pkce_s256},
						"response_type":         {string(osincli.CODE)},
					},
				},
				{
					method:   http.MethodPost,
					path:     "/oauth/token",
					response: `{"token_type": "access", "access_token": "secret"}`,
					parameters: map[string][]string{
						"code":          {"secret-auth-code"},
						"grant_type":    {string(osincli.AUTHORIZATION_CODE)},
						"code_verifier": {"code-challenge-plain"},
					},
				},
			},
			codeChallenge:      "code-challenge-encrypted",
			codeVerifier:       "code-challenge-plain",
			callbackParameters: url.Values{"code": []string{"secret-auth-code"}},
		},
		{
			name: "no code in callback",
			requests: []expectedRequest{
				{
					method: http.MethodHead, path: "/",
				},
				{
					method: http.MethodGet,
					path:   "/oauth/authorize",
					parameters: map[string][]string{
						"client_id":             {openShiftCLIBrowserClientID},
						"code_challenge":        {"code-challenge-encrypted"},
						"code_challenge_method": {pkce_s256},
						"response_type":         {string(osincli.CODE)},
					},
				},
			},
			codeChallenge: "code-challenge-encrypted",
			codeVerifier:  "code-challenge-plain",
			expectError:   "Requested parameter not sent",
		},
		{
			name: "no token after exchanging code",
			requests: []expectedRequest{
				{
					method: http.MethodHead, path: "/",
				},
				{
					method: http.MethodGet,
					path:   "/oauth/authorize",
					parameters: map[string][]string{
						"client_id":             {openShiftCLIBrowserClientID},
						"code_challenge":        {"code-challenge-encrypted"},
						"code_challenge_method": {pkce_s256},
						"response_type":         {string(osincli.CODE)},
					},
				},
				{
					method:   http.MethodPost,
					path:     "/oauth/token",
					response: "{}",
					parameters: map[string][]string{
						"code":          {"secret-auth-code"},
						"grant_type":    {string(osincli.AUTHORIZATION_CODE)},
						"code_verifier": {"code-challenge-plain"},
					},
				},
			},
			codeChallenge:      "code-challenge-encrypted",
			codeVerifier:       "code-challenge-plain",
			expectError:        "Invalid parameters received",
			callbackParameters: url.Values{"code": []string{"secret-auth-code"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := 0
			oauthServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if err := recover(); err != nil {
						t.Fatalf("test %s panicked: %v", tc.name, err)
					}
				}()

				if i >= len(tc.requests) {
					t.Fatalf("%s: %d: more requests received than expected: %#v", tc.name, i, r)
				}

				rr := tc.requests[i]
				i++

				method := rr.method
				if len(method) == 0 {
					method = http.MethodGet
				}
				if r.Method != method {
					t.Fatalf("%s: %d: Expected %s, got %s", tc.name, i, method, r.Method)
				}

				path := rr.path
				if r.URL.Path != path {
					t.Fatalf("%s: %d: Expected %s, got %s", tc.name, i, path, r.URL.Path)
				}

				switch r.Method {
				case http.MethodPost:
					err := r.ParseForm()
					if err != nil {
						t.Errorf("failed to parse request parameters: %v", err)
						return
					}
					if pDiff := parameterDiff(r.Form, rr.parameters); pDiff != "" {
						t.Errorf("unexpected POST parameters %s", pDiff)
					}
				case http.MethodGet:
					if pDiff := parameterDiff(r.URL.Query(), rr.parameters); pDiff != "" {
						t.Errorf("unexpected GET parameters %s", pDiff)
					}
				case http.MethodHead:
					return
				default:
					t.Fatalf("unknown method: %s", r.Method)
				}
				if rr.response != "" {
					w.Write([]byte(rr.response))
				}
			}))
			defer oauthServer.Close()

			o := RequestTokenOptions{
				ClientConfig: &restclient.Config{
					Host: oauthServer.URL,
					TLSClientConfig: restclient.TLSClientConfig{
						CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oauthServer.Certificate().Raw}),
					},
				},

				OsinConfig: &osincli.ClientConfig{
					ClientId:            openShiftCLIBrowserClientID,
					AuthorizeUrl:        oauthdiscovery.OpenShiftOAuthAuthorizeURL(oauthServer.URL),
					TokenUrl:            oauthdiscovery.OpenShiftOAuthTokenURL(oauthServer.URL),
					CodeChallengeMethod: pkce_s256,
					CodeChallenge:       tc.codeChallenge,
					CodeVerifier:        tc.codeVerifier,
				},
				Issuer: oauthServer.URL,
			}

			authzUrlHandler := func(tokenRequestURL *url.URL) error {
				client := oauthServer.Client()
				// get the redirect_uri from the parameters
				redirectURL := tokenRequestURL.Query().Get("redirect_uri")

				// proxy the call to the oauth server
				client.Timeout = 1 * time.Second
				_, err := client.Get(tokenRequestURL.String())
				if err != nil {
					return err
				}

				// make a request to the callback server
				http.DefaultClient.Timeout = 1 * time.Second
				_, err = http.PostForm(redirectURL, tc.callbackParameters)
				return err
			}

			_, err := o.WithLocalCallback(authzUrlHandler, 0)
			if err != nil {
				t.Errorf("%s: unexpected SetDefaultOsinConfig error: %v", tc.name, err)
				return
			}
			o.OsinConfig.RedirectUrl = fmt.Sprintf("http://%s/callback", o.LocalCallbackServer.listenAddr)

			token, err := o.requestTokenWithLocalCallback()
			if tc.expectError == "" {
				if err != nil {
					t.Errorf("failed to get token: %v", err)
					return
				}
				if token != "secret" {
					t.Errorf("access token is incorrect. Expected: %s Actual: %s", "secret", token)
				}
			}
			if tc.expectError != "" {
				if err == nil {
					t.Errorf("expected error instead got token %s", token)
					return
				}
				if !strings.Contains(err.Error(), tc.expectError) {
					t.Errorf(`expected error "%s", got error "%s"`, tc.expectError, err.Error())
					return
				}
			}
		})
	}
}

func TestConvertErrorIfUnknownX509(t *testing.T) {
	x509Err := errors.New("x509: certificate signed by unknown authority")
	otherErr := errors.New("some other error")

	for _, tc := range []struct {
		name string
		goos string
		err  error
		// wrapExpected is true when the error is expected to be wrapped in an
		// unknownX509VerificationError; otherwise the original error must be
		// returned unchanged.
		wrapExpected bool
	}{
		{
			name:         "nil error stays nil on darwin",
			goos:         "darwin",
			err:          nil,
			wrapExpected: false,
		},
		{
			name:         "x509-prefixed error is wrapped on darwin",
			goos:         "darwin",
			err:          x509Err,
			wrapExpected: true,
		},
		{
			name:         "non-x509 error is returned unchanged on darwin",
			goos:         "darwin",
			err:          otherErr,
			wrapExpected: false,
		},
		{
			name:         "x509-prefixed error is left unchanged on linux",
			goos:         "linux",
			err:          x509Err,
			wrapExpected: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := convertErrorIfUnknownX509(tc.goos, tc.err)

			if tc.wrapExpected {
				wrapped, ok := got.(unknownX509VerificationError)
				if !ok {
					t.Fatalf("expected unknownX509VerificationError, got %T: %v", got, got)
				}
				if !errors.Is(wrapped, tc.err) {
					t.Fatalf("expected the original error to be unwrappable, got %v", errors.Unwrap(wrapped))
				}
				return
			}

			// nil passes through as nil; on non-darwin (or non-x509 errors)
			// the original error is returned unchanged.
			if got != tc.err {
				t.Fatalf("expected the original error %v to be returned unchanged, got %T: %v", tc.err, got, got)
			}
		})
	}
}

func TestTransportWithRoots(t *testing.T) {
	// the probe request as the issuer saw it, reset by every subtest that
	// reaches a server
	var probeMethod, probePath, probeHost string
	recordProbe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeMethod, probePath, probeHost = r.Method, r.URL.Path, r.Host
	})

	// serves TLS with a self-signed certificate, i.e. one that is never part of
	// the system trust bundle, so the probe falls back to the kubeconfig CA
	tlsServer := httptest.NewTLSServer(recordProbe)
	defer tlsServer.Close()
	tlsServerURL, err := url.Parse(tlsServer.URL)
	if err != nil {
		t.Fatalf("unexpected error parsing the test server URL: %v", err)
	}

	// closed up front so that connecting to it is refused
	deadServer := httptest.NewTLSServer(recordProbe)
	deadServerURL := deadServer.URL
	deadServer.Close()

	caData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	missingCAFile := "/this/path/does/not/exist/ca.crt"

	// trusts the test server, standing in for the system trust bundle in the
	// cases that exercise successful validation of the serving certificate
	trustingRoots := x509.NewCertPool()
	trustingRoots.AddCert(tlsServer.Certificate())

	for _, tc := range []struct {
		name   string
		issuer string
		// roots stands in for the system trust bundle; nil means the real one,
		// which never trusts the self-signed test certificates.
		roots        *x509.CertPool
		clientConfig *restclient.Config
		expectError  string
		// expectProbePath and expectProbeHost, when set, are asserted against
		// the probe request as the issuer received it.
		expectProbePath string
		expectProbeHost string
		// target, when set, is requested with the returned transport to assert
		// which trust bundle the transport ended up with.
		target            string
		expectTargetError string
	}{
		{
			name:         "malformed issuer URL",
			issuer:       "https://exa\nmple.com",
			clientConfig: &restclient.Config{},
			expectError:  "invalid control character in URL",
		},
		{
			name:         "unreachable issuer",
			issuer:       deadServerURL,
			clientConfig: &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{CAData: caData}},
			expectError:  "connection refused",
		},
		// The three cases below pin which port the issuer is probed on, by way
		// of the address the failed dial reports. Note that they document the
		// behaviour rather than cover the port block in transportWithRoots:
		// the port an issuer is reached on is worked out by net/http from the
		// scheme, so these would keep passing if that block were deleted.
		//
		// They all use the IPv6 loopback so that the probe is refused
		// immediately, rather than waiting out a DNS lookup or a connect timeout.
		{
			name:         "https issuer without a port is probed on 443",
			issuer:       "https://[::1]/oauth/token",
			clientConfig: &restclient.Config{},
			expectError:  "dial tcp [::1]:443",
		},
		{
			// a plain HTTP issuer must not be probed on 443
			name:         "http issuer without a port is probed on 80",
			issuer:       "http://[::1]/oauth/token",
			clientConfig: &restclient.Config{},
			expectError:  "dial tcp [::1]:80",
		},
		{
			name:         "issuer with a port is probed on it",
			issuer:       "https://[::1]:8443/oauth/token",
			clientConfig: &restclient.Config{},
			expectError:  "dial tcp [::1]:8443",
		},
		{
			// the issuer already spells out a port, so the Host header it is
			// reached with must be unchanged
			name:            "issuer path and authority are preserved",
			issuer:          tlsServer.URL + "/oauth/token",
			clientConfig:    &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{CAData: caData}},
			expectProbePath: "/oauth/token",
			expectProbeHost: tlsServerURL.Host,
		},
		{
			name:         "self-signed issuer falls back to the kubeconfig CA",
			issuer:       tlsServer.URL,
			clientConfig: &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{CAData: caData}},
			target:       tlsServer.URL,
		},
		{
			name:   "self-signed issuer without a usable kubeconfig CA surfaces the error",
			issuer: tlsServer.URL,
			// the fallback transport cannot be built, which must be reported
			clientConfig: &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{CAFile: missingCAFile}},
			expectError:  missingCAFile,
		},
		{
			name:   "self-signed issuer with an empty kubeconfig CA keeps the system roots",
			issuer: tlsServer.URL,
			// nothing to fall back to, so the resulting transport does not trust
			// the issuer either - the assertion must not paper over that
			clientConfig:      &restclient.Config{},
			target:            tlsServer.URL,
			expectTargetError: "x509:",
		},
		{
			// same client config as the fallback case above, but the issuer now
			// validates against the roots, so the kubeconfig CA must be dropped:
			// the returned transport is left with roots that do not trust the
			// test server, hence the expected failure
			name:              "issuer trusted by the roots drops the kubeconfig CA",
			issuer:            tlsServer.URL,
			roots:             trustingRoots,
			clientConfig:      &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{CAData: caData}},
			target:            tlsServer.URL,
			expectTargetError: "x509:",
		},
		{
			// only the CA is unset when the system roots work, so the rest of the
			// kubeconfig TLS config still has to produce a usable transport
			name:   "issuer trusted by the roots surfaces client certificate errors",
			issuer: tlsServer.URL,
			roots:  trustingRoots,
			clientConfig: &restclient.Config{TLSClientConfig: restclient.TLSClientConfig{
				CAData:   caData,
				CertFile: "/this/path/does/not/exist/client.crt",
				KeyFile:  "/this/path/does/not/exist/client.key",
			}},
			expectError: "client.crt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probeMethod, probePath, probeHost = "", "", ""

			rt, err := transportWithRoots(tc.issuer, tc.clientConfig, tc.roots)

			if tc.expectError != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got transport %v", tc.expectError, rt)
				}
				if !strings.Contains(err.Error(), tc.expectError) {
					t.Fatalf("expected error containing %q, got %q", tc.expectError, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rt == nil {
				t.Fatal("expected a transport, got nil")
			}

			if tc.expectProbePath != "" {
				if probeMethod != http.MethodHead {
					t.Errorf("expected the issuer to be probed with %s, got %s", http.MethodHead, probeMethod)
				}
				if probePath != tc.expectProbePath {
					t.Errorf("expected the issuer to be probed at %q, got %q", tc.expectProbePath, probePath)
				}
				if probeHost != tc.expectProbeHost {
					t.Errorf("expected the issuer to be probed with Host %q, got %q", tc.expectProbeHost, probeHost)
				}
			}

			if tc.target == "" {
				return
			}

			req, err := http.NewRequest(http.MethodGet, tc.target, nil)
			if err != nil {
				t.Fatalf("unexpected error building the request: %v", err)
			}
			resp, err := rt.RoundTrip(req)
			if tc.expectTargetError != "" {
				if err == nil {
					resp.Body.Close()
					t.Fatalf("expected error containing %q, got status %s", tc.expectTargetError, resp.Status)
				}
				if !strings.Contains(err.Error(), tc.expectTargetError) {
					t.Fatalf("expected error containing %q, got %q", tc.expectTargetError, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error from the returned transport: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected %d from the returned transport, got %s", http.StatusOK, resp.Status)
			}
		})
	}
}

// TestTransportWithSystemRoots covers the wrapper production code actually
// calls. It passes a nil root pool down to transportWithRoots, meaning the real
// system trust bundle, which never trusts a self-signed test certificate, so
// the probe has to fall back to the CA from the kubeconfig.
func TestTransportWithSystemRoots(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsServer.Close()

	caData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})

	rt, err := transportWithSystemRoots(tlsServer.URL, &restclient.Config{
		TLSClientConfig: restclient.TLSClientConfig{CAData: caData},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rt == nil {
		t.Fatal("expected a transport, got nil")
	}

	// the transport is only usable against the test server if it kept the
	// kubeconfig CA, which is what the fallback is supposed to do
	req, err := http.NewRequest(http.MethodGet, tlsServer.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error building the request: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error from the returned transport: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected %d from the returned transport, got %s", http.StatusOK, resp.Status)
	}
}

func TestVerifyServerCertChain(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsServer.Close()

	chain := []*x509.Certificate{tlsServer.Certificate()}

	trustingRoots := x509.NewCertPool()
	trustingRoots.AddCert(tlsServer.Certificate())

	t.Run("empty chain", func(t *testing.T) {
		_, err := verifyServerCertChain("127.0.0.1", nil, trustingRoots)
		if err == nil {
			t.Fatal("expected an error for an empty certificate chain")
		}
		if !strings.Contains(err.Error(), "empty certificate chain") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("chain trusted by the given roots verifies", func(t *testing.T) {
		verified, err := verifyServerCertChain("127.0.0.1", chain, trustingRoots)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(verified) == 0 {
			t.Fatal("expected at least one verified chain")
		}
	})

	t.Run("hostname outside the certificate SANs is rejected", func(t *testing.T) {
		_, err := verifyServerCertChain("not-in-the-cert.example.org", chain, trustingRoots)
		if err == nil {
			t.Fatal("expected a hostname mismatch error")
		}
		var hostnameErr x509.HostnameError
		if !errors.As(err, &hostnameErr) {
			t.Fatalf("expected an x509.HostnameError, got %T: %v", err, err)
		}
	})

	t.Run("self-signed chain is not trusted by the system roots", func(t *testing.T) {
		if _, err := verifyServerCertChain("127.0.0.1", chain, nil); err == nil {
			t.Fatal("expected the self-signed certificate to fail verification")
		}
	})
}

func parameterDiff(input, expected map[string][]string) string {
	var diffs []string
	for key, values := range expected {
		inputValues := input[key]
		sortValues := cmp.Transformer("", func(i []string) []string { sort.Strings(i); return i })
		parameterDiff := cmp.Diff(values, inputValues, sortValues)
		if parameterDiff != "" {
			diffs = append(diffs, parameterDiff)
		}
	}
	return strings.Join(diffs, "\n")
}
