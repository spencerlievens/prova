// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2017 BitGo
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"time"

	"github.com/bitgo/prova/chaincfg/chainhash"
	"github.com/bitgo/prova/wire"
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network.
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x8e, 0x5b, 0xd1, 0xf4, 0xc9, 0x0b, 0x80, 0xd8,
				0xf3, 0x12, 0x2b, 0xf4, 0x62, 0x9a, 0x88, 0x21,
				0xc3, 0x6a, 0x70, 0x6d, 0x4c, 0xb1, 0x8b, 0xa9,
				0xa7, 0xa5, 0xe9, 0xa5, 0x87, 0xee, 0x48, 0xfe,
				/** From the Blockchain @ 475822 2017-07-14 */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			PkScript: []byte{
				0x00, 0xbb, // Root Thread Id, OP_CHECKTHREAD
			},
		},
		{
			PkScript: []byte{
				0x51, 0xbb, // Provision Thread, OP_CHECKTHREAD
			},
		},
		{
			PkScript: []byte{
				0x52, 0xbb, // Issue Thread, OP_CHECKTHREAD
			},
		},
	},
}

// testGenesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the regression test network, and test network.
var testGenesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x35, 0x80, 0x85, 0x7b, 0xe1, 0x75, 0xc7,
				0xd5, 0x77, 0xb8, 0x5d, 0xb2, 0xe0, 0x06, 0xd5,
				0xb8, 0x91, 0x4e, 0x64, 0xab, 0xb7, 0x87, 0x1c,
				/** From the Blockchain @ 459254 2017-03-28 */
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			PkScript: []byte{
				0x00, 0xbb, // Root Thread Id, OP_CHECKTHREAD
			},
		},
		{
			PkScript: []byte{
				0x51, 0xbb, // Provision Thread, OP_CHECKTHREAD
			},
		},
		{
			PkScript: []byte{
				0x52, 0xbb, // Issue Thread, OP_CHECKTHREAD
			},
		},
	},
}

// genesisHash is the hash of the first block in the block chain for the main
// network (genesis block).
// TODO(prova): Make this a constant rather than computed, once genesis block is finalized
var genesisHash = genesisBlock.Header.BlockHash()

// coinbaseMerkleRoot calculates the merkle root of a genesis block from
// the coinbase.
func coinbaseMerkleRoot(coinbase wire.MsgTx) chainhash.Hash {
	left := coinbase.TxHash()
	right := coinbase.TxHashWithSig()
	// Concatenate the left and right nodes.
	var hash [chainhash.HashSize * 2]byte
	copy(hash[:chainhash.HashSize], left[:])
	copy(hash[chainhash.HashSize:], right[:])
	return chainhash.DoubleHashH(hash[:])
}

// genesisMerkleRoot is the hash of the first transaction in the genesis block
// for the main network.
var genesisMerkleRoot = coinbaseMerkleRoot(genesisCoinbaseTx)

// testGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test networks.
var testGenesisMerkleRoot = coinbaseMerkleRoot(testGenesisCoinbaseTx)

// genesisBlock defines the genesis block of the block chain which serves as the
// public transaction ledger for the main network.
var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    4,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x58DC307C, 0), // 2017-03-29 22:09:00 +0000 UTC
		Bits:       0x1d00ffff,               // 486604799 [00000000ffff0000000000000000000000000000000000000000000000000000]
		Nonce:      0xab821115,               // 2877427989,
		Size:       326,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

// regTestGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the regression test network.  It is the same as the merkle root for
// the main network.
var regTestGenesisMerkleRoot = coinbaseMerkleRoot(testGenesisCoinbaseTx)

// regTestGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the regression test network.
var regTestGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    4,
		PrevBlock:  chainhash.Hash{}, // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: regTestGenesisMerkleRoot,
		Timestamp:  time.Unix(0x58DC307C, 0), // 2017-03-29 22:09:00 +0000 UTC
		Bits:       0x200f0f0f,               // 537857807 [0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f]
		Nonce:      9,
		Size:       326,
	},
	Transactions: []*wire.MsgTx{&testGenesisCoinbaseTx},
}

// regTestGenesisHash is the hash of the first block in the block chain for the
// regression test network (genesis block).
// TODO(prova): Make this a constant rather than computed, once genesis block is finalized
var regTestGenesisHash = regTestGenesisBlock.Header.BlockHash()

// testNetGenesisHash is the hash of the first block in the block chain for the
// test network.
// TODO(prova): Make this a constant rather than computed, once genesis block is finalized
var testNetGenesisHash = testNetGenesisBlock.Header.BlockHash()

// testNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the test network.  It is the same as the merkle root for the main
// network.
var testNetGenesisMerkleRoot = testGenesisMerkleRoot

// testNetGenesisBlock defines the genesis block of the block chain which
// serves as the public transaction ledger for the test network.
var testNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    4,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: testNetGenesisMerkleRoot, // 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
		Timestamp:  time.Unix(0x58DC307C, 0), // 2017-03-29 22:09:00 +0000 UTC
		Bits:       0x2007ffff,               // 537395199 [07ffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      1,
		Size:       326,
	},
	Transactions: []*wire.MsgTx{&testGenesisCoinbaseTx},
}

// simNetGenesisHash is the hash of the first block in the block chain for the
// simulation test network.
var simNetGenesisHash = simNetGenesisBlock.Header.BlockHash()

// simNetGenesisMerkleRoot is the hash of the first transaction in the genesis
// block for the simulation test network.  It is the same as the merkle root for
// the test network.
var simNetGenesisMerkleRoot = testGenesisMerkleRoot

// simNetGenesisBlock defines the genesis block of the block chain which serves
// as the public transaction ledger for the simulation test network.
var simNetGenesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    4,
		PrevBlock:  chainhash.Hash{}, // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: simNetGenesisMerkleRoot,
		Timestamp:  time.Unix(0x58DC307C, 0), // 2017-03-29 22:09:00 +0000 UTC
		Bits:       0x207fffff,               // 545259519 [7fffff0000000000000000000000000000000000000000000000000000000000]
		Nonce:      2,
		Size:       326,
	},
	Transactions: []*wire.MsgTx{&testGenesisCoinbaseTx},
}
