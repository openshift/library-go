package tokenrequest

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
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

	"github.com/RangelReale/osincli"
	"github.com/google/go-cmp/cmp"

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
			Handler: challengehandlers.NewBasicChallengeHandler("", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, success": {
			Handler: challengehandlers.NewBasicChallengeHandler("", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic+negotiate challenge, success": {
			Handler: challengehandlers.NewBasicChallengeHandler("", bytes.NewBufferString("mypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, doubleChallenge},
				{basicRequest1, success},
			},
			ExpectedToken: successfulToken,
		},
		"prompting basic handler, basic challenge, failure": {
			Handler: challengehandlers.NewBasicChallengeHandler("", nil, nil, &testPasswordPrompter{}, "myuser", ""),
			Requests: []requestResponse{
				{initialHead, initialHeadResp},
				{initialRequest, basicChallenge1},
				{basicRequestOnlyUsername, basicChallenge2},
			},
			ExpectedError: "challenger chose not to retry the request",
		},
		"prompting basic handler, negotiate challenge, failure": {
			Handler: challengehandlers.NewBasicChallengeHandler("", bytes.NewBufferString("myuser\nmypassword\n"), nil, &testPasswordPrompter{}, "myuser", ""),
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
			t.Errorf("%s: expected osin config does not match, %s", tc.name, diff.ObjectDiff(*tc.expectedConfig, *opts.OsinConfig))
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
