// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain_test

import (
	"testing"

	"github.com/bitgo/rmgd/blockchain"
	"github.com/bitgo/rmgd/chaincfg/chainhash"
	"github.com/bitgo/btcutil"
)

// TestMerkle tests the BuildMerkleTreeStore API.
func TestMerkle(t *testing.T) {
	block := btcutil.NewBlock(&Block100000)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions())
	calculatedMerkleRoot := merkles[len(merkles)-1]
	// TODO(aztec) clean this up and generate a new block with correct merkle root
	merkleStr := "229149a594ba8828b0721bc471c74572adcc1f0af7b7ae8b0834fa487bcd2acf"
	wantMerkle, _ := chainhash.NewHashFromStr(merkleStr)
	if !wantMerkle.IsEqual(calculatedMerkleRoot) {
		t.Errorf("BuildMerkleTreeStore: merkle root mismatch - "+
			"got %v, want %v", calculatedMerkleRoot, wantMerkle)
	}
}
