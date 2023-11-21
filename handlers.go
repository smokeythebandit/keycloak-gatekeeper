/*
Copyright 2015 All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"net/http"
	"net/http/pprof"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	gcsrf "github.com/gorilla/csrf"
	"github.com/oneconcern/keycloak-gatekeeper/version"

	"github.com/go-chi/chi"
	"go.uber.org/zap"
)

// getRedirectionURL returns the redirectionURL for the oauth flow
func (r *oauthProxy) getRedirectionURL(w http.ResponseWriter, req *http.Request) string {
	ctx, span, logger := r.traceSpan(req.Context(), "getRedirectionURL")
	if span != nil {
		defer span.End()
	}

	var redirect string
	switch r.config.RedirectionURL {
	case "":
		// need to determine the scheme, cx.Request.URL.Scheme doesn't have it, best way is to default
		// and then check for TLS
		scheme := unsecureScheme
		if req.TLS != nil {
			scheme = secureScheme
		}
		// @QUESTION: should I use the X-Forwarded-<header>?? ..
		redirect = fmt.Sprintf("%s://%s",
			defaultTo(req.Header.Get("X-Forwarded-Proto"), scheme),
			defaultTo(req.Header.Get("X-Forwarded-Host"), req.Host))
	default:
		redirect = r.config.RedirectionURL
	}

	state, _ := req.Cookie(requestStateCookie)
	if state != nil && req.URL.Query().Get("state") != state.Value {
		logger.Error("state in cookie and url query parameter do not match", zap.String("cookie-state", state.Value),
			zap.String("url-state", req.URL.Query().Get("state")))
		// clear all cookies in response
		r.clearAllCookies(req, w)
		r.errorResponse(w, req.WithContext(ctx), "state parameter mismatch", http.StatusForbidden, nil)
		return ""
	}
	return fmt.Sprintf("%s%s", redirect, r.config.WithOAuthURI("callback"))
}

// oauthAuthorizationHandler is responsible for performing the redirection to oauth provider
func (r *oauthProxy) oauthAuthorizationHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, logger := r.traceSpan(req.Context(), "authorization handler")
	if span != nil {
		defer span.End()
	}

	if r.config.SkipTokenVerification {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusNotAcceptable, nil)
		return
	}

	client, err := r.getOAuthClient(r.getRedirectionURL(w, req.WithContext(ctx)))
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), "failed to retrieve the oauth client for authorization", http.StatusInternalServerError, err)
		return
	}

	// step: set the access type of the session
	var accessType string
	if containedIn("offline", r.config.Scopes, false) {
		accessType = "offline"
	}

	authURL := client.AuthCodeURL(req.URL.Query().Get("state"), accessType, "")
	logger.Debug("incoming authorization request from client address",
		zap.String("access_type", accessType),
		zap.String("auth_url", authURL),
		zap.String("client_ip", req.RemoteAddr))

	// step: if we have a custom sign in page, lets display that
	if r.config.hasCustomSignInPage() {
		model := make(map[string]string)
		model["redirect"] = authURL
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = r.Render(w, path.Base(r.config.SignInPage), mergeMaps(model, r.config.Tags))

		return
	}

	user := req.URL.Query().Get("username")
	pass := req.URL.Query().Get("password")

	logger.Info("TTESTT1 have user and pass",
		zap.String("user", user),
		zap.String("pass", pass))
	if user != "" && pass != "" {
		newParams := url.Values{
			"username": {user},
			"password": {pass},
		}
		q := newParams.Encode()
		authURL = authURL + "&" + q
	}

	logger.Info("TTESTT2 authURL",
		zap.String("authURL", authURL))

	r.redirectToURL(authURL, w, req.WithContext(ctx), http.StatusTemporaryRedirect)
}

// oauthCallbackHandler is responsible for handling the response from oauth service
func (r *oauthProxy) oauthCallbackHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, logger := r.traceSpan(req.Context(), "oauthCallbackHandler")
	if span != nil {
		defer span.End()
	}

	if r.config.SkipTokenVerification {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusNotAcceptable, nil)
		return
	}
	// step: ensure we have a authorization code
	code := req.URL.Query().Get("code")
	if code == "" {
		r.errorResponse(w, req.WithContext(ctx), "no code in query", http.StatusBadRequest, nil)
		return
	}

	client, err := r.getOAuthClient(r.getRedirectionURL(w, req.WithContext(ctx)))
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), "unable to create a oauth2 client", http.StatusInternalServerError, err)
		return
	}

	resp, err := exchangeAuthenticationCode(client, code)
	if err != nil {
		r.accessForbidden(w, req.WithContext(ctx), "unable to exchange code for access token", err.Error())
		return
	}

	// Flow: once we exchange the authorization code we parse the ID Token; we then check for an access token,
	// if an access token is present and we can decode it, we use that as the session token, otherwise we default
	// to the ID Token.
	token, identity, err := parseToken(resp.IDToken)
	if err != nil {
		r.accessForbidden(w, req.WithContext(ctx), "unable to parse ID token for identity", err.Error())

		return
	}
	access, id, err := parseToken(resp.AccessToken)
	if err == nil {
		token = access
		identity = id
	} else {
		logger.Warn("unable to parse the access token, using id token only", zap.Error(err))
	}

	// step: check the access token is valid
	if err = r.verifyToken(r.client, token); err != nil {
		// if not, we may have a valid session but fail to match extra criteria: logout first so the user does not remain
		// stuck with a valid session, but no access
		var sessionToken string
		if resp.RefreshToken != "" {
			sessionToken = resp.RefreshToken
		} else {
			sessionToken = resp.IDToken
		}
		r.commonLogout(ctx, w, req, sessionToken, func(ww http.ResponseWriter) {
			// always return an error after logout in this case
			r.accessForbidden(w, req.WithContext(ctx), "unable to verify the ID token", err.Error())
		}, logger.With(zap.String("email", identity.Email)))

		return
	}
	accessToken := token.Encode()

	// step: are we encrypting the access token?
	if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
		if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
			r.errorResponse(w, req.WithContext(ctx), "unable to encode the access token", http.StatusInternalServerError, err)

			return
		}
	}

	logger.Info("issuing access token for user",
		zap.String("email", identity.Email),
		zap.String("expires", identity.ExpiresAt.Format(time.RFC3339)),
		zap.String("duration", time.Until(identity.ExpiresAt).String()))

	// @metric a token has been issued
	oauthTokensMetric.WithLabelValues("issued").Inc()

	// step: does the response have a refresh token and we do NOT ignore refresh tokens?
	if r.config.EnableRefreshTokens && resp.RefreshToken != "" {
		var encrypted string
		encrypted, err = encodeText(resp.RefreshToken, r.config.EncryptionKey)
		if err != nil {
			r.errorResponse(w, req.WithContext(ctx), "failed to encrypt the refresh token", http.StatusInternalServerError, err)
			return
		}

		// drop in the access token - cookie expiration = access token
		r.dropAccessTokenCookie(req.WithContext(ctx), w, accessToken, r.getAccessCookieExpiration(token, resp.RefreshToken))

		switch r.useStore() {
		case true:
			if err = r.StoreRefreshToken(token, encrypted); err != nil {
				logger.Warn("failed to save the refresh token in the store", zap.Error(err))
			}
		default:
			// notes: not all idp refresh tokens are readable, google for example, so we attempt to decode into
			// a jwt and if possible extract the expiration, else we default to 10 days
			if _, ident, err := parseToken(resp.RefreshToken); err != nil {
				r.dropRefreshTokenCookie(req.WithContext(ctx), w, encrypted, 0)
			} else {
				r.dropRefreshTokenCookie(req.WithContext(ctx), w, encrypted, time.Until(ident.ExpiresAt))
			}
		}
	} else {
		r.dropAccessTokenCookie(req.WithContext(ctx), w, accessToken, time.Until(identity.ExpiresAt))
	}

	// step: decode the request variable
	redirectURI := "/"
	if req.URL.Query().Get("state") != "" {
		// if the authorization has set a state, we now check if the calling client
		// requested a specific landing URL to end the authentication handshake
		if encodedRequestURI, _ := req.Cookie(requestURICookie); encodedRequestURI != nil {
			// some clients URL-escape padding characters
			unescapedValue, err := url.PathUnescape(encodedRequestURI.Value)
			if err != nil {
				logger.Warn("app did send a corrupted redirectURI in cookie: invalid url espcaping", zap.Error(err))
			}
			// Since the value is passed with a cookie, we do not expect the client to use base64url (but the
			// base64-encoded value may itself be url-encoded).
			// This is safe for browsers using atob() but needs to be treated with care for nodeJS clients,
			// which natively use base64url encoding, and url-escape padding '=' characters.
			decoded, err := base64.StdEncoding.DecodeString(unescapedValue)
			if err != nil {
				logger.Warn("app did send a corrupted redirectURI in cookie: invalid base64url encoding",
					zap.Error(err),
					zap.String("encoded_value", unescapedValue))
			}
			redirectURI = string(decoded)
		}
	}

	if r.config.BaseURI != "" {
		// assuming state starts with slash
		redirectURI = r.config.BaseURI + redirectURI
	}

	r.redirectToURL(redirectURI, w, req.WithContext(ctx), http.StatusTemporaryRedirect)
}

// loginHandler provide's a generic endpoint for clients to perform a user_credentials login to the provider
func (r *oauthProxy) loginHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, _ := r.traceSpan(req.Context(), "login handler")
	if span != nil {
		defer span.End()
	}

	errorMsg, code, err := func() (string, int, error) {
		if !r.config.EnableLoginHandler {
			return "attempt to login when login handler is disabled", http.StatusNotImplemented, errors.New("login handler disabled")
		}
		username := req.PostFormValue("username")
		password := req.PostFormValue("password")
		if username == "" || password == "" {
			return "request does not have both username and password", http.StatusBadRequest, errors.New("no credentials")
		}

		client, err := r.client.OAuthClient()
		if err != nil {
			return "unable to create the oauth client for user_credentials request", http.StatusInternalServerError, err
		}

		start := time.Now()
		token, err := client.UserCredsToken(username, password)
		if err != nil {
			if strings.HasPrefix(err.Error(), oauth2.ErrorInvalidGrant) {
				return "invalid user credentials provided", http.StatusUnauthorized, err
			}
			return "unable to request the access token via grant_type 'password'", http.StatusInternalServerError, err
		}
		// @metric observe the time taken for a login request
		oauthLatencyMetric.WithLabelValues("login").Observe(time.Since(start).Seconds())

		_, identity, err := parseToken(token.AccessToken)
		if err != nil {
			return "unable to decode the access token", http.StatusNotImplemented, err
		}

		r.dropAccessTokenCookie(req.WithContext(ctx), w, token.AccessToken, time.Until(identity.ExpiresAt))

		// @metric a token has been issued
		oauthTokensMetric.WithLabelValues("login").Inc()

		w.Header().Set("Content-Type", jsonMime)
		err = json.NewEncoder(w).Encode(tokenResponse{
			IDToken:      token.IDToken,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresIn:    token.Expires,
			Scope:        token.Scope,
		})
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		return "", http.StatusOK, nil
	}()
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), strings.Join([]string{errorMsg, "client_ip", req.RemoteAddr}, ","), code, err)
	}
}

// emptyHandler is responsible for doing nothing
func emptyHandler(w http.ResponseWriter, req *http.Request) {}

// logoutHandler performs a logout
//   - if it's just a access token, the cookie is deleted
//   - if the user has a refresh token, the token is invalidated by the provider
//   - optionally, the user can be redirected by to a url
func (r *oauthProxy) logoutHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, logger := r.traceSpan(req.Context(), "logout handler")
	if span != nil {
		defer span.End()
	}

	// @step: drop the access token
	user, err := r.getIdentity(req)
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusBadRequest, nil)
		return
	}

	// step: check if the user has a state session and if so revoke it
	if r.useStore() {
		go func() {
			if err := r.DeleteRefreshToken(user.token); err != nil {
				logger.Error("unable to remove the refresh token from store", zap.Error(err))
			}
		}()
	}

	// step: can either use the id token or the refresh token
	identityToken := user.token.Encode()
	if refresh, _, err := r.retrieveRefreshToken(req, user); err == nil {
		identityToken = refresh
	}

	r.commonLogout(ctx, w, req, identityToken, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", jsonMime)
		w.WriteHeader(http.StatusOK)
	}, logger.With(zap.String("email", user.email)))
}

func (r *oauthProxy) commonLogout(ctx context.Context, w http.ResponseWriter, req *http.Request, token string, successResponder func(http.ResponseWriter), logger Logger) {
	// @metric increment the logout counter
	oauthTokensMetric.WithLabelValues("logout").Inc()

	r.clearAllCookies(req, w)

	// @check if the redirection is there
	var redirectURL string
	for k := range req.URL.Query() {
		if k == "redirect" {
			redirectURL = req.URL.Query().Get("redirect")
			if redirectURL == "" {
				// we can default to redirection url
				redirectURL = strings.TrimSuffix(r.config.RedirectionURL, "/oauth/callback")
			}
		}
	}

	// set the default revocation url
	revokeDefault := ""
	if r.idp.EndSessionEndpoint != nil {
		revokeDefault = r.idp.EndSessionEndpoint.String()
	}
	revocationURL := defaultTo(r.config.RevocationEndpoint, revokeDefault)
	logger.Debug("logout config",
		zap.String("redirect_url", redirectURL),
		zap.String("revocation_url", revocationURL),
		zap.Bool("enable_logout_redirect", r.config.EnableLogoutRedirect),
	)

	// @check if we should redirect to the provider
	// NOTE: this endpoint is keycloak-specific
	if r.config.EnableLogoutRedirect {
		sendTo := fmt.Sprintf("%s/protocol/openid-connect/logout", strings.TrimSuffix(r.config.DiscoveryURL, "/.well-known/openid-configuration"))

		// @step: if no redirect uri is set
		if redirectURL == "" {
			// @step: we first check for a redirection-url and then host header
			if r.config.RedirectionURL != "" {
				redirectURL = r.config.RedirectionURL
			} else {
				redirectURL = getRequestHostURL(req)
			}
		}

		logger.Debug("redirecting to logout", zap.String("url", sendTo))
		r.redirectToURL(fmt.Sprintf("%s?redirect_uri=%s", sendTo, url.QueryEscape(redirectURL)), w, req, http.StatusTemporaryRedirect)

		return
	}

	// step: do we have a revocation endpoint?
	if revocationURL != "" {
		client, err := r.client.OAuthClient()
		if err != nil {
			//nolint:contextcheck
			r.errorResponse(w, req.WithContext(ctx), "unable to retrieve the openid client", http.StatusInternalServerError, err)
			return
		}

		// step: add the authentication headers
		encodedID := url.QueryEscape(r.config.ClientID)
		encodedSecret := url.QueryEscape(r.config.ClientSecret)

		logger.Debug("revoking user session")
		// step: construct the url for revocation
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, revocationURL, bytes.NewBufferString(fmt.Sprintf("refresh_token=%s", token)))
		if err != nil {
			//nolint:contextcheck
			r.errorResponse(w, req.WithContext(ctx), "unable to construct the revocation request", http.StatusInternalServerError, err)
			return
		}

		// step: add the authentication headers and content-type
		request.SetBasicAuth(encodedID, encodedSecret)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		start := time.Now()
		response, err := client.HttpClient().Do(request)
		if err != nil {
			logger.Error("unable to post to revocation endpoint", zap.Error(err))
			return
		}
		defer func() {
			_ = response.Body.Close()
		}()

		oauthLatencyMetric.WithLabelValues("revocation").Observe(time.Since(start).Seconds())

		// step: check the response
		switch response.StatusCode {
		case http.StatusNoContent:
			logger.Info("successfully logged out of the endpoint")
		default:
			content, _ := io.ReadAll(response.Body)
			logger.Error("invalid response from revocation endpoint",
				zap.Int("status", response.StatusCode),
				zap.ByteString("response", content))
		}
	}

	// step: should we redirect the user
	if redirectURL != "" {
		logger.Debug("redirecting to logout", zap.String("url", redirectURL))
		r.redirectToURL(redirectURL, w, req.WithContext(ctx), http.StatusTemporaryRedirect)
	} else {
		successResponder(w)
	}
}

// expirationHandler checks if the token has expired
func (r *oauthProxy) expirationHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, _ := r.traceSpan(req.Context(), "expiration handler")
	if span != nil {
		defer span.End()
	}

	user, err := r.getIdentity(req)
	if err != nil || user.isExpired() {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusUnauthorized, nil)
		return
	}
	w.Header().Set("Content-Type", jsonMime)
	w.WriteHeader(http.StatusOK)
}

// refreshHandler forces a token refresh
func (r *oauthProxy) refreshHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, logger := r.traceSpan(req.Context(), "token refresh handler")
	if span != nil {
		defer span.End()
	}

	user, err := r.getIdentity(req)
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusUnauthorized, nil)
		return
	}

	if !r.config.EnableRefreshTokens {
		clientIP := req.RemoteAddr
		logger.Warn("access token refresh is disabled",
			zap.String("client_ip", clientIP),
			zap.String("email", user.name),
			zap.String("expired_on", user.expiresAt.String()))
		w.Header().Set("Content-Type", jsonMime)
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}

	if err = r.refreshToken(w, req.WithContext(ctx), user); err != nil {
		switch err {
		case ErrEncode, ErrEncryption:
			r.errorResponse(w, req.WithContext(ctx), err.Error(), http.StatusInternalServerError, err)
		default:
			r.errorResponse(w, req.WithContext(ctx), err.Error(), http.StatusUnauthorized, err)
		}
		return
	}

	w.Header().Set("Content-Type", jsonMime)
	_, _ = w.Write(user.token.Payload)
	w.WriteHeader(http.StatusOK)
}

// tokenHandler display access token to screen
func (r *oauthProxy) tokenHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, _ := r.traceSpan(req.Context(), "token handler")
	if span != nil {
		defer span.End()
	}

	user, err := r.getIdentity(req)
	if err != nil {
		r.errorResponse(w, req.WithContext(ctx), "", http.StatusUnauthorized, nil)
		return
	}
	w.Header().Set("Content-Type", jsonMime)
	_, _ = w.Write(user.token.Payload)
	w.WriteHeader(http.StatusOK)
}

// healthHandler is a health check handler for the service
func (r *oauthProxy) healthHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", jsonMime)
	w.Header().Set(versionHeader, version.GetVersion())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"OK"}`))
}

// debugHandler is responsible for providing the pprof
func (r *oauthProxy) debugHandler(w http.ResponseWriter, req *http.Request) {
	ctx, span, _ := r.traceSpan(req.Context(), "debug handler")
	if span != nil {
		defer span.End()
	}

	const symbolProfile = "symbol"
	name := chi.URLParam(req, "name")
	switch req.Method {
	case http.MethodGet:
		switch name {
		case "heap", "goroutine", "allocs", "block", "threadcreate", "mutex":
			// predefined profiles
			pprof.Handler(name).ServeHTTP(w, req.WithContext(ctx))
		case "cmdline":
			pprof.Cmdline(w, req)
		case "profile":
			// cpu profile
			pprof.Profile(w, req)
		case "trace":
			pprof.Trace(w, req)
		case symbolProfile:
			pprof.Symbol(w, req)
		default:
			r.errorResponse(w, req.WithContext(ctx), "", http.StatusNotFound, nil)
		}
	case http.MethodPost:
		switch name {
		case symbolProfile:
			pprof.Symbol(w, req)
		default:
			r.errorResponse(w, req.WithContext(ctx), "", http.StatusNotFound, nil)
		}
	}
}

// retrieveRefreshToken retrieves the refresh token from store or cookie
func (r *oauthProxy) retrieveRefreshToken(req *http.Request, user *userContext) (token, encrypted string, err error) {
	switch r.useStore() {
	case true:
		token, err = r.GetRefreshToken(user.token)
	default:
		token, err = r.getRefreshTokenFromCookie(req)
	}
	if err != nil {
		return
	}

	encrypted = token // returns encrypted, avoids encoding twice
	token, err = decodeText(token, r.config.EncryptionKey)
	return
}

func (r *oauthProxy) csrfErrorHandler(w http.ResponseWriter, req *http.Request) {
	r.accessForbidden(w, req, "CSRF error", gcsrf.FailureReason(req).Error(), req.RemoteAddr)
}

func (r *oauthProxy) refreshToken(w http.ResponseWriter, req *http.Request, user *userContext) error {
	ctx, span, logger := r.traceSpan(req.Context(), "logout handler")
	if span != nil {
		defer span.End()
	}

	clientIP := req.RemoteAddr

	// step: check if the user has refresh token
	refresh, encrypted, err := r.retrieveRefreshToken(req.WithContext(ctx), user)
	if err != nil {
		logger.Warn("unable to find a refresh token for user",
			zap.String("client_ip", clientIP),
			zap.String("email", user.email),
			zap.Error(err))
		return err
	}

	// attempt to refresh the access token, possibly with a renewed refresh token
	//
	// NOTE: atm, this does not retrieve explicit refresh token expiry from oauth2,
	// and take identity expiry instead: with keycloak, they are the same and equal to
	// "SSO session idle" keycloak setting.
	//
	// exp: expiration of the access token
	// expiresIn: expiration of the ID token

	token, newRefreshToken, accessExpiresAt, refreshExpiresIn, err := getRefreshedToken(r.client, refresh)
	if err != nil {
		switch err {
		case ErrRefreshTokenExpired:
			logger.Warn("refresh token has expired, cannot retrieve access token",
				zap.String("client_ip", clientIP),
				zap.String("email", user.email))

			r.clearAllCookies(req, w)
		default:
			r.log.Error("failed to refresh the access token", zap.Error(err))
		}

		return err
	}

	accessExpiresIn := time.Until(accessExpiresAt)

	// get the expiration of the new refresh token
	if newRefreshToken != "" {
		refresh = newRefreshToken
	}
	if refreshExpiresIn == 0 {
		// refresh token expiry claims not available: try to parse refresh token
		refreshExpiresIn = r.getAccessCookieExpiration(token, refresh)
	}

	logger.Info("injecting the refreshed access token cookie",
		zap.String("client_ip", clientIP),
		zap.String("cookie_name", r.config.CookieAccessName),
		zap.String("email", user.email),
		zap.Duration("refresh_expires_in", refreshExpiresIn),
		zap.Duration("expires_in", accessExpiresIn))

	accessToken := token.Encode()
	if r.config.EnableEncryptedToken || r.config.ForceEncryptedCookie {
		// encrypt access token
		if accessToken, err = encodeText(accessToken, r.config.EncryptionKey); err != nil {
			logger.Error("internal error while encoding access token",
				zap.String("client_ip", clientIP), zap.String("email", user.email), zap.Error(err))
			return ErrEncode
		}
	}

	// step: inject the refreshed access token
	r.dropAccessTokenCookie(req.WithContext(ctx), w, accessToken, accessExpiresIn)

	// step: inject the renewed refresh token
	if newRefreshToken != "" {
		logger.Debug("renew refresh cookie with new refresh token",
			zap.Duration("refresh_expires_in", refreshExpiresIn))
		encryptedRefreshToken, err := encodeText(newRefreshToken, r.config.EncryptionKey)
		if err != nil {
			logger.Error("internal error while encrypting refresh token",
				zap.String("client_ip", clientIP), zap.String("email", user.email), zap.Error(err))
			return ErrEncryption
		}
		r.dropRefreshTokenCookie(req.WithContext(ctx), w, encryptedRefreshToken, refreshExpiresIn)
	}

	if r.useStore() {
		go func(oldToken, newToken jose.JWT, encrypted string) {
			if err := r.DeleteRefreshToken(oldToken); err != nil {
				logger.Error("failed to remove old token", zap.Error(err))
			}

			if err := r.StoreRefreshToken(newToken, encrypted); err != nil {
				logger.Error("failed to store refresh token", zap.Error(err))
				return
			}
		}(user.token, token, encrypted)
	}

	// update the user with the new access token and inject into the context
	user.token = token
	return nil
}

func (r *oauthProxy) forbiddenHandler(w http.ResponseWriter, req *http.Request) {
	r.accessForbidden(w, req, "access denied")
}
