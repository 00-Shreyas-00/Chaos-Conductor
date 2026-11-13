//go:build integration

package repository

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

var randReader = rand.Reader

func randHashHex(t *testing.T) string { return hex.EncodeToString(randHash(t)) }
