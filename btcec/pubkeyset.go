// Copyright (c) 2017 The BitGo developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"encoding/hex"
)

type KeySetType uint8

const (
	RootKeySet      KeySetType = 0
	ProvisionKeySet KeySetType = 1
	IssueKeySet     KeySetType = 2
	ValidateKeySet  KeySetType = 3
)

// ParsePubKeySet parses a list of ecdsa.Publickey for a koblitz curve from a
// list of hex encoded strings, verifying that it is valid.
func ParsePubKeySet(curve *KoblitzCurve, pubKeys ...string) (PublicKeySet, error) {
	keys := make([]PublicKey, len(pubKeys))

	for i, pubKeyStr := range pubKeys {
		key, err := ParsePubKey(hexToBytes(pubKeyStr), curve)
		if err != nil {
			return nil, err
		}
		keys[i] = *key
	}
	return PublicKeySet(keys), nil
}

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// PublicKeySet is a Set of ecdsa.PublicKey with basic functions to
// add, remove, serialize.
type PublicKeySet []PublicKey

// Pos returns the position of a public key in keyset.
// -1 is returned if element not found.
// This is a basic collection operation, golang should have it out of the box.
func (set PublicKeySet) Pos(key *PublicKey) int {
	for p, v := range set {
		if v.IsEqual(key) {
			return p
		}
	}
	return -1
}

// ToStringArray returns a string array of serialized keys.
func (set PublicKeySet) ToStringArray() []string {
	rv := make([]string, len(set))
	for i, v := range set {
		rv[i] = hex.EncodeToString(v.SerializeCompressed())
	}
	return rv
}

func (set PublicKeySet) Add(key *PublicKey) PublicKeySet {
	if set.Pos(key) < 0 {
		set = append(set, *key)
	}
	return set
}

// remove will remove the element at position i.
func (set PublicKeySet) Remove(pos int) PublicKeySet {
	if pos < 0 || pos >= len(set) {
		return set
	}
	//move element at pos to end of set through assignment
	set[len(set)-1], set[pos] = set[pos], set[len(set)-1]
	//cut last element off
	return set[:len(set)-1]
}

// Equal will compare two key sets.
func (set PublicKeySet) Equal(v PublicKeySet) bool {
	if set == nil && v == nil {
		return true
	}
	if set == nil || v == nil {
		return false
	}
	if len(set) != len(v) {
		return false
	}
	for i := range set {
		if !set[i].IsEqual(&v[i]) {
			return false
		}
	}
	return true
}
