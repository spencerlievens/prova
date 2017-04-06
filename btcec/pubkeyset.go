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
	ASPKeySet       KeySetType = 4
)

// String returns the key set type as a human-readable string.
func (kstype KeySetType) String() string {
	switch kstype {
	case RootKeySet:
		return "ROOT"
	case ProvisionKeySet:
		return "PROVISION"
	case IssueKeySet:
		return "ISSUE"
	case ValidateKeySet:
		return "VALIDATE"
	case ASPKeySet:
		return "ASP"
	default:
		return ""
	}
}

// ParsePubKeySet parses a list of ecdsa.Publickey for a koblitz curve from a
// list of hex encoded strings, verifying that they are valid.
func ParsePubKeySet(curve *KoblitzCurve, pubKeys ...string) (PublicKeySet, error) {
	keys := make([]PublicKey, len(pubKeys))

	for i, pubKeyStr := range pubKeys {
		keyBytes, err := hex.DecodeString(pubKeyStr)
		if err != nil {
			return nil, err
		}
		key, err := ParsePubKey(keyBytes, curve)
		if err != nil {
			return nil, err
		}
		keys[i] = *key
	}
	return PublicKeySet(keys), nil
}

// DeepCopy creates a deep copy of the admin keys.
func DeepCopy(adminKeySets map[KeySetType]PublicKeySet) map[KeySetType]PublicKeySet {
	copiedMap := make(map[KeySetType]PublicKeySet)
	for setType, keySet := range adminKeySets {
		copiedMap[setType] = make([]PublicKey, len(keySet))
		copy(copiedMap[setType], keySet)
	}
	return copiedMap
}

// PublicKeySet is a set of ecdsa.PublicKey with basic functions to add,
// remove, and serialize.
type PublicKeySet []PublicKey

// Pos returns the position of a public key in keyset. Should the public key be
// absent from the keyset, -1 is returned to indicate the key was not found.
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

// Add appends a public key to the public key set, if it is not already present.
func (set PublicKeySet) Add(key *PublicKey) PublicKeySet {
	if set.Pos(key) < 0 {
		set = append(set, *key)
	}
	return set
}

// Remove removes a public key at a specified index from the public key set.
func (set PublicKeySet) Remove(pos int) PublicKeySet {
	if pos < 0 || pos >= len(set) {
		return set
	}
	//move element at pos to end of set through assignment
	set[len(set)-1], set[pos] = set[pos], set[len(set)-1]
	//cut last element off
	return set[:len(set)-1]
}

// Equal compares the public key set to the one passed, returning true if both
// sets are equivalent.
func (set PublicKeySet) Equal(v PublicKeySet) bool {
	if set == nil && v == nil {
		return true
	}
	if set == nil && len(v) != 0 || v == nil && len(set) != 0 {
		return false
	}
	if len(set) != len(v) {
		return false
	}
	for i := range v {
		if &v[i] == nil || set.Pos(&v[i]) == -1 {
			return false
		}
	}
	return true
}
