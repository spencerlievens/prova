// Copyright (c) 2017 BitGo Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import ()

// KeyIdMap is a structure to keep assigned keyIDs and pubKeys.
type KeyIdMap map[KeyID]*PublicKey

// Equal will compare two slices.
func (keyMap KeyIdMap) Equal(v KeyIdMap) bool {
	if keyMap == nil && v == nil {
		return true
	}
	if len(keyMap) != len(v) {
		return false
	}
	for keyID, _ := range keyMap {
		if !keyMap[keyID].IsEqual(v[keyID]) {
			return false
		}
	}
	return true
}
