// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
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
	wspKeyIdMap  btcec.KeyIdMap
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

// SetKeys sets the admin key sets at the position in the chain the view
// curretly represents.
func (view *KeyViewpoint) SetKeys(keys map[btcec.KeySetType]btcec.PublicKeySet) {
	if keys != nil {
		view.adminKeySets = keys
	}
}

// Keys returns the set current admin key sets.
func (view *KeyViewpoint) Keys() map[btcec.KeySetType]btcec.PublicKeySet {
	return view.adminKeySets
}

// GetAdminKeyHashes returns pubKeyHashes according to the provided threadID.
func (view *KeyViewpoint) GetAdminKeyHashes(threadID rmgutil.ThreadID) ([][]byte, error) {

	if threadID > rmgutil.IssueThread {
		return nil, fmt.Errorf("unknown threadID %v", threadID)
	}

	pubs := view.adminKeySets[btcec.KeySetType(threadID)]
	sort.Sort(ByPubKey{PublicKeys(pubs)})
	hashes := make([][]byte, len(pubs))
	for i, pubKey := range pubs {
		hashes[i] = rmgutil.Hash160(pubKey.SerializeCompressed())
	}
	return hashes, nil
}

// SetKeyIDs sets the mapping of keyIDs to WSP keys.
func (view *KeyViewpoint) SetKeyIDs(wspKeyIdMap btcec.KeyIdMap) {
	if wspKeyIdMap != nil {
		view.wspKeyIdMap = wspKeyIdMap
	}
}

// KeyIDs returns a mapping of keyIDs to WSP keys at the position in the chain
// the view currently represents.
func (view *KeyViewpoint) KeyIDs() btcec.KeyIdMap {
	return view.wspKeyIdMap
}

// LookupKeyIDs returns pubKeyHashes for all registered KeyIDs
func (view *KeyViewpoint) LookupKeyIDs(keyIDs []btcec.KeyID) map[btcec.KeyID][]byte {
	keyIdMap := make(map[btcec.KeyID][]byte)
	for _, keyID := range keyIDs {
		pubKey := view.wspKeyIdMap[keyID]
		if pubKey != nil {
			keyIdMap[keyID] = rmgutil.Hash160(pubKey.SerializeCompressed())
		}
	}
	return keyIdMap
}

// ProcessAdminOuts finds admin transactions and executes all ops in it.
// This function is called after the validity of the transaction has been
// verified.
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
		op, pubKey, _ := txscript.ExtractAdminData(adminOutputs[i])
		switch threadID {
		case rmgutil.RootThread:
			if op == txscript.OP_PROVISIONINGKEYADD {
				view.adminKeySets[btcec.ProvisionKeySet] = view.adminKeySets[btcec.ProvisionKeySet].Add(pubKey)
			}
			if op == txscript.OP_PROVISIONINGKEYREVOKE {
				pos := view.adminKeySets[btcec.ProvisionKeySet].Pos(pubKey)
				view.adminKeySets[btcec.ProvisionKeySet] = view.adminKeySets[btcec.ProvisionKeySet].Remove(pos)
			}
			if op == txscript.OP_ISSUINGKEYADD {
				view.adminKeySets[btcec.IssueKeySet] = view.adminKeySets[btcec.IssueKeySet].Add(pubKey)
			}
			if op == txscript.OP_ISSUINGKEYREVOKE {
				pos := view.adminKeySets[btcec.IssueKeySet].Pos(pubKey)
				view.adminKeySets[btcec.IssueKeySet] = view.adminKeySets[btcec.IssueKeySet].Remove(pos)
			}
		case rmgutil.ProvisionThread:
			if op == txscript.OP_VALIDATEKEYADD {
				view.adminKeySets[btcec.ValidateKeySet] = view.adminKeySets[btcec.ValidateKeySet].Add(pubKey)
			}
			if op == txscript.OP_VALIDATEKEYREVOKE {
				pos := view.adminKeySets[btcec.ValidateKeySet].Pos(pubKey)
				view.adminKeySets[btcec.ValidateKeySet] = view.adminKeySets[btcec.ValidateKeySet].Remove(pos)
			}
			if op == txscript.OP_WSPKEYADD {
				_, pubKey, keyID, _ := txscript.ExtractWspData(adminOutputs[i])
				if view.wspKeyIdMap[keyID] == nil {
					view.wspKeyIdMap[keyID] = pubKey
				}
			}
			if op == txscript.OP_WSPKEYREVOKE {
				_, pubKey, keyID, _ := txscript.ExtractWspData(adminOutputs[i])
				if view.wspKeyIdMap[keyID].IsEqual(pubKey) {
					delete(view.wspKeyIdMap, keyID)
				}
			}
		}
	}
}

// PublicKeys is a wrapper for the btcec.PublicKey array to allow sorting.
type PublicKeys []btcec.PublicKey

// Len to implement the sort interface.
func (pubs PublicKeys) Len() int {
	return len(pubs)
}

// Swap to implement the sort interface.
func (pubs PublicKeys) Swap(i, j int) {
	pubs[i], pubs[j] = pubs[j], pubs[i]
}

// ByPubKey implements sort.Interface by providing Less and using the Len and
// Swap methods of the embedded PublicKeys value.
type ByPubKey struct {
	PublicKeys
}

// Less compares two private keys to determine order. The key are compared by
// deriving the public keys, and comparing lexicographically.
func (s ByPubKey) Less(i, j int) bool {
	pubKeyI := &s.PublicKeys[i]
	pubKeyStrI := fmt.Sprintf("%x", pubKeyI.SerializeCompressed())

	pubKeyJ := &s.PublicKeys[j]
	pubKeyStrJ := fmt.Sprintf("%x", pubKeyJ.SerializeCompressed())
	return pubKeyStrI < pubKeyStrJ
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
				op, pubKey, _ := txscript.ExtractAdminData(adminOutputs[i])
				switch threadID {
				case rmgutil.RootThread:
					if op == txscript.OP_PROVISIONINGKEYREVOKE {
						view.adminKeySets[btcec.ProvisionKeySet] = view.adminKeySets[btcec.ProvisionKeySet].Add(pubKey)
					}
					if op == txscript.OP_PROVISIONINGKEYADD {
						pos := view.adminKeySets[btcec.ProvisionKeySet].Pos(pubKey)
						view.adminKeySets[btcec.ProvisionKeySet] = view.adminKeySets[btcec.ProvisionKeySet].Remove(pos)
					}
					if op == txscript.OP_ISSUINGKEYREVOKE {
						view.adminKeySets[btcec.IssueKeySet] = view.adminKeySets[btcec.IssueKeySet].Add(pubKey)
					}
					if op == txscript.OP_ISSUINGKEYADD {
						pos := view.adminKeySets[btcec.IssueKeySet].Pos(pubKey)
						view.adminKeySets[btcec.IssueKeySet] = view.adminKeySets[btcec.IssueKeySet].Remove(pos)
					}
				case rmgutil.ProvisionThread:
					if op == txscript.OP_VALIDATEKEYREVOKE {
						view.adminKeySets[btcec.ValidateKeySet] = view.adminKeySets[btcec.ValidateKeySet].Add(pubKey)
					}
					if op == txscript.OP_VALIDATEKEYADD {
						pos := view.adminKeySets[btcec.ValidateKeySet].Pos(pubKey)
						view.adminKeySets[btcec.ValidateKeySet] = view.adminKeySets[btcec.ValidateKeySet].Remove(pos)
					}
					if op == txscript.OP_WSPKEYREVOKE {
						_, pubKey, keyID, _ := txscript.ExtractWspData(adminOutputs[i])
						if view.wspKeyIdMap[keyID] == nil {
							view.wspKeyIdMap[keyID] = pubKey
						}
					}
					if op == txscript.OP_WSPKEYADD {
						_, pubKey, keyID, _ := txscript.ExtractWspData(adminOutputs[i])
						if view.wspKeyIdMap[keyID].IsEqual(pubKey) {
							delete(view.wspKeyIdMap, keyID)
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
		wspKeyIdMap:  make(map[btcec.KeyID]*btcec.PublicKey),
	}
}
