// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain_test

import (
	"testing"
	"time"

	"github.com/bitgo/rmgd/blockchain"
	"github.com/bitgo/rmgd/chaincfg"
	"github.com/bitgo/rmgd/chaincfg/chainhash"
	"github.com/bitgo/rmgd/rmgutil"
	"github.com/bitgo/rmgd/wire"
)

// TestCalcBlockSubsidy tests the block subsidy calculation to ensure it
// returns the expected subsidy value.
func TestCalcBlockSubsidy(t *testing.T) {
	subsidy := blockchain.CalcBlockSubsidy(0, &chaincfg.MainNetParams)

	if subsidy != 5000*rmgutil.AtomsPerGram {
		t.Errorf("TestCalcBlockSubsidy: inconsistent initial block "+
			"subsidy %v", subsidy)
	}
}

// TestCheckConnectBlock tests the CheckConnectBlock function to ensure it
// fails.
func TestCheckConnectBlock(t *testing.T) {
	// Create a new database and chain instance to run tests against.
	chain, teardownFunc, err := chainSetup("checkconnectblock",
		&chaincfg.MainNetParams)
	if err != nil {
		t.Errorf("Failed to setup chain instance: %v", err)
		return
	}
	defer teardownFunc()

	// The genesis block should fail to connect since it's already inserted.
	genesisBlock := chaincfg.MainNetParams.GenesisBlock
	err = chain.CheckConnectBlock(rmgutil.NewBlock(genesisBlock))
	if err == nil {
		t.Errorf("CheckConnectBlock: Did not received expected error")
	}
}

// TestCheckBlockSanity tests the CheckBlockSanity function to ensure it works
// as expected.
func TestCheckBlockSanity(t *testing.T) {
	powLimit := chaincfg.MainNetParams.PowLimit
	block := rmgutil.NewBlock(&SomeBlock)
	timeSource := blockchain.NewMedianTime()
	err := blockchain.CheckBlockSanity(block, powLimit, timeSource)
	if err != nil {
		t.Errorf("CheckBlockSanity: %v", err)
	}

	// Ensure a block that has a timestamp with a precision higher than one
	// second fails.
	timestamp := block.MsgBlock().Header.Timestamp
	block.MsgBlock().Header.Timestamp = timestamp.Add(time.Nanosecond)
	err = blockchain.CheckBlockSanity(block, powLimit, timeSource)
	if err == nil {
		t.Errorf("CheckBlockSanity: error is nil when it shouldn't be")
	}
}

// SomeBlock is used to test Block operations.
var SomeBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash([32]byte{119, 45, 217, 219, 98, 171, 237, 137, 252, 106, 160, 236, 130, 80, 139, 241, 92, 104, 211, 86, 65, 166, 88, 18, 125, 35, 43, 22, 129, 219, 112, 44}),
		MerkleRoot: chainhash.Hash([32]byte{248, 53, 49, 152, 191, 87, 162, 223, 132, 68, 215, 125, 18, 36, 14, 37, 29, 27, 141, 50, 2, 62, 204, 216, 18, 164, 54, 199, 110, 74, 23, 254}),
		Timestamp:  time.Unix(1486467380, 0), //
		Bits:       0x2000000f,               //
		Size:       0x00000132,               // 306
		Nonce:      0x00000019,               // 25
	},
	Transactions: []*wire.MsgTx{
		{
			Version: 1,
			TxIn: []*wire.TxIn{
				{
					PreviousOutPoint: wire.OutPoint{
						Hash:  chainhash.Hash{},
						Index: 0xffffffff,
					},
					SignatureScript: []byte{
						0x06, 0x2f, 0x72, 0x6d, 0x67, 0x64, 0x2f,
					},
					Sequence: 0xffffffff,
				},
			},
			TxOut: []*wire.TxOut{
				{
					Value:    0x1388, // 5000
					PkScript: []byte{82, 20, 53, 219, 191, 4, 188, 160, 97, 228, 157, 172, 224, 143, 133, 141, 135, 117, 192, 165, 124, 142, 3, 0, 0, 1, 81, 83, 186},
				},
			},
			LockTime: 0,
		},
	},
}
