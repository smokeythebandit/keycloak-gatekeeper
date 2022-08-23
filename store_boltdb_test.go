//go:build !nostores && !race
// +build !nostores,!race

// NOTE: boltdb test no longer supports race tests

/*
Copyright 2017 All rights reserved.

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
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeBoltDBStore struct {
	storedb *os.File
	store   *boltdbStore
}

func (f *fakeBoltDBStore) close() {
	if f.storedb != nil {
		f.storedb.Close()
		os.Remove(f.storedb.Name())
	}
}

func newTestBoldDB(t testing.TB) *fakeBoltDBStore {
	tmpfile, err := os.CreateTemp("/tmp", "keycloak-gatekeeper")
	if err != nil {
		t.Fatalf("unable to create temporary file, error: %s", err)
	}
	u, err := url.Parse(fmt.Sprintf("file:///%s", tmpfile.Name()))
	if err != nil {
		t.Fatalf("unable to parse file url, error: %s", err)
	}
	s, err := newBoltDBStore(u)
	if err != nil {
		_ = tmpfile.Close()
		_ = os.Remove(tmpfile.Name())
		t.Fatalf("unable to test boltdb, error: %s", err)
	}
	store, ok := s.(*boltdbStore)
	require.True(t, ok)

	return &fakeBoltDBStore{tmpfile, store}
}

func TestNewBoltDBStore(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()

	assert.NotNil(t, s)
}

func TestBoltSet(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()

	assert.NoError(t,
		s.store.Set("test", "value"),
	)
}

func TestBoltGet(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()

	v, err := s.store.Get("test")
	assert.NoError(t, err)
	assert.Empty(t, v)

	assert.NoError(t,
		s.store.Set("test", "value"),
	)

	v, err = s.store.Get("test")
	assert.NoError(t, err)
	assert.Equal(t, "value", v)
}

func TestBoltDelete(t *testing.T) {
	keyname := "test"
	value := "value"
	s := newTestBoldDB(t)
	defer s.close()

	assert.NoError(t,
		s.store.Set(keyname, value),
	)

	v, err := s.store.Get(keyname)
	assert.NoError(t, err)
	assert.Equal(t, value, v)

	assert.NoError(t,
		s.store.Delete(keyname),
	)

	v, err = s.store.Get(keyname)
	assert.NoError(t, err)
	assert.Empty(t, v)
}

func TestBoldClose(t *testing.T) {
	s := newTestBoldDB(t)
	defer s.close()

	assert.NoError(t,
		s.store.Close(),
	)
}

func TestCreateStorageBoltDB(t *testing.T) {
	store, err := createStorage("boltdb:////tmp/bolt")
	assert.NotNil(t, store)
	assert.NoError(t, err)
	if store != nil {
		os.Remove("/tmp/bolt")
	}
}
