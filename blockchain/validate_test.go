// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain_test

import (
	"bytes"
	"github.com/bitgo/rmgd/blockchain"
	"github.com/bitgo/rmgd/btcec"
	"github.com/bitgo/rmgd/chaincfg"
	"github.com/bitgo/rmgd/chaincfg/chainhash"
	"github.com/bitgo/rmgd/rmgutil"
	"github.com/bitgo/rmgd/txscript"
	"github.com/bitgo/rmgd/wire"
	"testing"
	"time"
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

// TestCheckTransactionSanity tests the CheckTransactionSanity API.
func TestCheckTransactionSanity(t *testing.T) {
	// Create some dummy, but otherwise standard, data for transactions.
	prevOutHash, err := chainhash.NewHashFromStr("01")
	if err != nil {
		t.Fatalf("NewShaHashFromStr: unexpected error: %v", err)
	}
	dummyPrevOut1 := wire.OutPoint{Hash: *prevOutHash, Index: 1}
	dummyPrevOut2 := wire.OutPoint{Hash: *prevOutHash, Index: 2}
	dummySigScript := bytes.Repeat([]byte{0x00}, 65)
	dummyTxIn := wire.TxIn{
		PreviousOutPoint: dummyPrevOut1,
		SignatureScript:  dummySigScript,
		Sequence:         wire.MaxTxInSequenceNum,
	}
	dummyTxIn2 := wire.TxIn{
		PreviousOutPoint: dummyPrevOut2,
		SignatureScript:  dummySigScript,
		Sequence:         wire.MaxTxInSequenceNum,
	}

	// Create some dummy admin op output.
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte{
		0x2b, 0x8c, 0x52, 0xb7, 0x7b, 0x32, 0x7c, 0x75,
		0x5b, 0x9b, 0x37, 0x55, 0x00, 0xd3, 0xf4, 0xb2,
		0xda, 0x9b, 0x0a, 0x1f, 0xf6, 0x5f, 0x68, 0x91,
		0xd3, 0x11, 0xfe, 0x94, 0x29, 0x5b, 0xc2, 0x6a,
	})
	data := make([]byte, 1+btcec.PubKeyBytesLenCompressed)
	data[0] = txscript.OP_PROVISIONINGKEYADD
	copy(data[1:], pubKey.SerializeCompressed())
	adminOpPkScript, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
		AddData(data).Script()
	adminOpTxOut := wire.TxOut{
		Value:    0, // 0 RMG
		PkScript: adminOpPkScript,
	}
	// create root tx out
	rootPkScript, _ := txscript.AztecThreadScript(rmgutil.RootThread)
	rootTxOut := wire.TxOut{
		Value:    0, // 0 RMG
		PkScript: rootPkScript,
	}
	// create provision tx out
	provisionPkScript, _ := txscript.AztecThreadScript(rmgutil.ProvisionThread)
	provisionTxOut := wire.TxOut{
		Value:    0, // 0 RMG
		PkScript: provisionPkScript,
	}

	tests := []struct {
		name       string
		tx         wire.MsgTx
		isStandard bool
		code       blockchain.ErrorCode
	}{
		{
			name: "Typical admin transaction",
			tx: wire.MsgTx{
				Version:  1,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&rootTxOut, &adminOpTxOut},
				LockTime: 0,
			},
			isStandard: true,
		},
		{
			name: "admin transaction with thread output at pos 1.",
			tx: wire.MsgTx{
				Version:  1,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&adminOpTxOut, &rootTxOut},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
		{
			name: "admin transaction with non-zero output value.",
			tx: wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{&rootTxOut, {
					Value:    500,
					PkScript: adminOpPkScript,
				}},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
		{
			name: "admin transaction with more than 1 input.",
			tx: wire.MsgTx{
				Version:  1,
				TxIn:     []*wire.TxIn{&dummyTxIn, &dummyTxIn2},
				TxOut:    []*wire.TxOut{&rootTxOut, &adminOpTxOut},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
		{
			name: "Empty admin transaction",
			tx: wire.MsgTx{
				Version:  1,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&rootTxOut},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
		{
			name: "Admin transaction with operation on wrong thread",
			tx: wire.MsgTx{
				Version:  1,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&provisionTxOut, &adminOpTxOut},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
		{
			name: "Admin transaction with invalid operation",
			tx: wire.MsgTx{
				Version: 1,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{&rootTxOut, {
					Value:    0,
					PkScript: []byte{txscript.OP_RETURN},
				}},
				LockTime: 0,
			},
			isStandard: false,
			code:       blockchain.ErrInvalidAdminTx,
		},
	}

	for _, test := range tests {
		// Ensure standardness is as expected.
		err := blockchain.CheckTransactionSanity(rmgutil.NewTx(&test.tx))
		if err == nil && test.isStandard {
			// Test passes since function returned standard for a
			// transaction which is intended to be standard.
			continue
		}
		if err == nil && !test.isStandard {
			t.Errorf("checkTransactionStandard (%s): standard when "+
				"it should not be", test.name)
			continue
		}
		if err != nil && test.isStandard {
			t.Errorf("checkTransactionStandard (%s): nonstandard "+
				"when it should not be: %v", test.name, err)
			continue
		}

		// Ensure error type is a TxRuleError inside of a RuleError.
		rerr, ok := err.(blockchain.RuleError)
		if !ok {
			t.Errorf("checkTransactionStandard (%s): unexpected "+
				"error type - got %T", test.name, err)
			continue
		}
		//txrerr, ok := rerr.Err.(TxRuleError)
		if !ok {
			t.Errorf("checkTransactionStandard (%s): unexpected "+
				"error type - got %T", test.name, rerr.ErrorCode)
			continue
		}

		// Ensure the reject code is the expected one.
		if rerr.ErrorCode != test.code {
			t.Errorf("checkTransactionStandard (%s): unexpected "+
				"error code - got %v, want %v", test.name,
				rerr.ErrorCode, test.code)
			continue
		}
	}
}
