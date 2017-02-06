// Copyright (c) 2017 BitGo Inc.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"encoding/binary"
)

const KeyIDSize = 4

type KeyID uint32

func (id KeyID) ToAddressFormat(buf []byte) {
	binary.LittleEndian.PutUint32(buf, uint32(id))
}

func KeyIDFromAddressBuffer(buf []byte) KeyID {
	id := binary.LittleEndian.Uint32(buf)
	return KeyID(id)
}
