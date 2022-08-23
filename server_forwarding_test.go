//go:build !noforwarding
// +build !noforwarding

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwardingProxy(t *testing.T) {
	cfg := newFakeKeycloakConfig()
	cfg.EnableForwarding = true
	cfg.ForwardingDomains = []string{}
	cfg.ForwardingUsername = validUsername
	cfg.ForwardingPassword = validPassword
	s := httptest.NewServer(&fakeUpstreamService{})
	requests := []fakeRequest{
		{
			URL:                     s.URL + "/test",
			ProxyRequest:            true,
			ExpectedProxy:           true,
			ExpectedCode:            http.StatusOK,
			ExpectedContentContains: "Bearer ey",
		},
	}
	p := newFakeProxy(cfg)
	defer func() {
		t.Log("waiting for the forward proxy to relinquish goroutines")
		p.proxy.forwardCancel()
		_ = p.proxy.forwardWaitGroup.Wait()
	}()

	<-time.After(time.Duration(100) * time.Millisecond)
	p.RunTests(t, requests)
}
