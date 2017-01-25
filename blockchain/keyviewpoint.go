// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"encoding/hex"
	"fmt"
	"github.com/bitgo/rmgd/btcec"
	"github.com/bitgo/rmgd/chaincfg/chainhash"
	"github.com/bitgo/rmgd/rmgutil"
	"github.com/bitgo/rmgd/txscript"
	"sort"
)

// KeyViewpoint represents a view into the set of admin keys from a specific
// point of view in the chain. For example, it could be for the end of the main
// chain, some point in the history of the main chain, or down a side chain.
type KeyViewpoint struct {
	adminKeySets map[btcec.KeySetType]btcec.PublicKeySet
	bestHash     chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *KeyViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *KeyViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// IssuingKeys returns the set of valid issuing keys.
func (view *KeyViewpoint) Keys() map[btcec.KeySetType]btcec.PublicKeySet {
	return view.adminKeySets
}

// SetKeys returns the set of valid issuing keys.
func (view *KeyViewpoint) SetKeys(keys map[btcec.KeySetType]btcec.PublicKeySet) {
	view.adminKeySets = keys
}

// LookupKeyIDs returns pubKeyHashes for all registered KeyIDs
// TODO(aztec) replace static lookup with dynamic one from utxView
func (view *KeyViewpoint) LookupKeyIDs(keyIDs []rmgutil.KeyID) map[rmgutil.KeyID][]byte {
	keyIdMap := make(map[rmgutil.KeyID][]byte)
	for _, keyID := range keyIDs {
		keyIdMap[keyID] = []byte{53, 219, 191, 4, 188, 160, 97, 228, 157, 172, 224, 143, 133, 141, 135, 117, 192, 165, 124, 142}
		if keyID == 1 {
			keyIdMap[keyID] = []byte{207, 85, 250, 254, 141, 22, 106, 190, 101, 133, 28, 207, 125, 127, 53, 172, 186, 5, 176, 249}
		}
	}
	return keyIdMap
}

// GetAdminKeyHashes returns pubKeyHashes according to the provided threadID.
// TODO(aztec) replace static with dynamic list
func (view *KeyViewpoint) GetAdminKeyHashes(threadID rmgutil.ThreadID) ([][]byte, error) {
	rootKeyPubs := []string{
		// priv eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694
		"025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1",
		// priv 2b8c52b77b327c755b9b375500d3f4b2da9b0a1ff65f6891d311fe94295bc26a
		"038ef4a121bcaf1b1f175557a12896f8bc93b095e84817f90e9a901cd2113a8202"}
	provisionKeyPubs := []string{
		// priv eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694
		"025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1",
		// priv 2b8c52b77b327c755b9b375500d3f4b2da9b0a1ff65f6891d311fe94295bc26a
		"038ef4a121bcaf1b1f175557a12896f8bc93b095e84817f90e9a901cd2113a8202",
		// priv 6e6b5b6ff0fc11cea9c0949595cfb01b8c268325b564d0d74cd77e4348b06177
		"02cf712ca1d7784bc0c381c250f2a7c7f2729da771abaaca5772201c6103575bb8",
		// priv 7bb53c8506695b19f9d6d863748d91efccd948b768984761d4de5d69ca2d3847
		"03ecf4f686b7528197f6e58183e7c76f6dad16c38d6e5ce2ac73e469fda56f5f0e",
		// priv 07cf1bf3bd286649f837df98c1737af40ec62d7da9581b34c529c7f894f7e3e3
		"038e8031f881cdbf553abf7c59d22183e8333bea265eabe4e9d8aa762fe9fe619c"}
	issueKeyPubs := []string{
		// priv eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694
		"025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1",
		// priv 2b8c52b77b327c755b9b375500d3f4b2da9b0a1ff65f6891d311fe94295bc26a
		"038ef4a121bcaf1b1f175557a12896f8bc93b095e84817f90e9a901cd2113a8202"}
	adminKeyPubs := [3][]string{rootKeyPubs, provisionKeyPubs, issueKeyPubs}

	if int(threadID) >= len(adminKeyPubs) {
		return nil, fmt.Errorf("unknown threadID %v", threadID)
	}

	pubs := adminKeyPubs[threadID]
	sort.Strings(pubs)
	hashes := make([][]byte, len(pubs))
	for i, pubKeyStr := range pubs {
		pubKeyBytes, err := hex.DecodeString(pubKeyStr)
		if err != nil {
			return nil, err
		}
		pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256())
		if err != nil {
			return nil, err
		}
		hashes[i] = rmgutil.Hash160(pubKey.SerializeCompressed())
	}
	return hashes, nil
}

// ProcessAdminOuts finds admin transactions and executes all ops in it
// TODO(aztec): add more threads and ops.
func (view *KeyViewpoint) ProcessAdminOuts(tx *rmgutil.Tx, blockHeight uint32) {
	threadInt, adminOutputs := txscript.GetAdminDetails(tx)
	if threadInt < int(rmgutil.RootThread) {
		// Not admin transaction.
		// Not all transaction that we receive are relevant, so we skip them.
		return
	}
	threadID := rmgutil.ThreadID(threadInt)
	for i := 0; i < len(adminOutputs); i++ {
		switch threadID {
		case rmgutil.ProvisionThread:
			op, pubKey, _ := txscript.ExtractAdminData(adminOutputs[i])
			if op == txscript.OP_ISSUINGKEYADD {
				if view.adminKeySets[btcec.IssuingKeySet].Pos(pubKey) < 0 {
					view.adminKeySets[btcec.IssuingKeySet] = append(view.adminKeySets[btcec.IssuingKeySet], *pubKey)
				}
			}
			if op == txscript.OP_ISSUINGKEYREVOKE {
				pos := view.adminKeySets[btcec.IssuingKeySet].Pos(pubKey)
				if pos >= 0 {
					view.adminKeySets[btcec.IssuingKeySet] = view.adminKeySets[btcec.IssuingKeySet].Remove(pos)
				}
			}
		}
	}
}

// connectTransaction updates the view by processing all new admin operations in
// the passed transaction.
func (view *KeyViewpoint) connectTransaction(tx *rmgutil.Tx, blockHeight uint32) error {
	// Process the admin outputs that are part of this tx.
	view.ProcessAdminOuts(tx, blockHeight)
	return nil
}

// connectTransactions updates the view by processing all the admin operations
// in created by all of the transactions in the passed block.
func (view *KeyViewpoint) connectTransactions(block *rmgutil.Block) error {
	for _, tx := range block.Transactions() {
		err := view.connectTransaction(tx, block.Height())
		if err != nil {
			return err
		}
	}
	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}

// disconnectTransactions updates the view by undoing all admin operations in
// all of the transactions contained in the passed block, and setting the best
// hash for the view to the block before the passed block.
func (view *KeyViewpoint) disconnectTransactions(block *rmgutil.Block) error {

	// Loop backwards through all transactions so operations are undone in
	// reverse order.
	transactions := block.Transactions()
	for txIdx := len(transactions) - 1; txIdx >= 0; txIdx-- {
		tx := transactions[txIdx]

		// If an admin transaction is disconnected, undo what it did to chain state.
		// TODO(aztec): execute more than the first op.
		// TODO(aztec): add more threads and ops.
		threadInt, adminOutputs := txscript.GetAdminDetails(tx)
		if threadInt >= int(rmgutil.RootThread) {
			threadID := rmgutil.ThreadID(threadInt)
			for i := 0; i < len(adminOutputs); i++ {
				switch threadID {
				case rmgutil.ProvisionThread:
					op, pubKey, _ := txscript.ExtractAdminData(adminOutputs[i])
					if op == txscript.OP_ISSUINGKEYREVOKE {
						if view.adminKeySets[btcec.IssuingKeySet].Pos(pubKey) < 0 {
							view.adminKeySets[btcec.IssuingKeySet] = append(view.adminKeySets[btcec.IssuingKeySet], *pubKey)
						}
					}
					if op == txscript.OP_ISSUINGKEYADD {
						pos := view.adminKeySets[btcec.IssuingKeySet].Pos(pubKey)
						if pos >= 0 {
							view.adminKeySets[btcec.IssuingKeySet] = view.adminKeySets[btcec.IssuingKeySet].Remove(pos)
						}
					}
				}
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// NewKeyViewpoint returns a new empty key view.
func NewKeyViewpoint() *KeyViewpoint {
	return &KeyViewpoint{
		adminKeySets: make(map[btcec.KeySetType]btcec.PublicKeySet),
	}
}
