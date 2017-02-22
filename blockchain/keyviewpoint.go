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
	threadTips   map[rmgutil.ThreadID]*chainhash.Hash
	lastKeyID    btcec.KeyID
	totalSupply  uint64
	adminKeySets map[btcec.KeySetType]btcec.PublicKeySet
	wspKeyIdMap  btcec.KeyIdMap
}

// ThreadTips returns
func (view *KeyViewpoint) ThreadTips() map[rmgutil.ThreadID]*chainhash.Hash {
	return view.threadTips
}

// SetThreadTips sets
func (view *KeyViewpoint) SetThreadTips(
	threadTips map[rmgutil.ThreadID]*chainhash.Hash) {
	view.threadTips = threadTips
}

// LastKeyID returns
func (view *KeyViewpoint) LastKeyID() btcec.KeyID {
	return view.lastKeyID
}

// SetLastKeyID sets
func (view *KeyViewpoint) SetLastKeyID(lastKeyID btcec.KeyID) {
	view.lastKeyID = lastKeyID
}

// TotalSupply returns
func (view *KeyViewpoint) TotalSupply() uint64 {
	return view.totalSupply
}

// SetTotalSupply sets
func (view *KeyViewpoint) SetTotalSupply(totalSupply uint64) {
	view.totalSupply = totalSupply
}

// SetKeys sets the admin key sets at the position in the chain the view
// curretly represents.
func (view *KeyViewpoint) SetKeys(keys map[btcec.KeySetType]btcec.PublicKeySet) {
	if keys != nil {
		view.adminKeySets = btcec.DeepCopy(keys)
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
func (view *KeyViewpoint) ProcessAdminOuts(tx *rmgutil.Tx, blockHeight uint32) {
	threadInt, adminOutputs := txscript.GetAdminDetails(tx)
	if threadInt < 0 ||
		rmgutil.ThreadID(threadInt) == rmgutil.IssueThread {
		// Issue Thread, or not admin transaction
		return // so we skip.
	}
	for i := 0; i < len(adminOutputs); i++ {
		isAddOp, keySetType, pubKey,
			keyID := txscript.ExtractAdminOpData(adminOutputs[i])
		view.applyAdminOp(isAddOp, keySetType, pubKey, keyID)
	}
	// this becomes the new tip of the admin thread
	threadId := rmgutil.ThreadID(threadInt)
	view.threadTips[threadId] = tx.Hash()
}

// applyAdminOp takes a single admin opp and applies it to the view.
func (view *KeyViewpoint) applyAdminOp(isAddOp bool,
	keySetType btcec.KeySetType, pubKey *btcec.PublicKey, keyID btcec.KeyID) {
	if keySetType == btcec.WspKeySet {
		if isAddOp {
			view.wspKeyIdMap[keyID] = pubKey
			view.lastKeyID = keyID
		} else {
			delete(view.wspKeyIdMap, keyID)
		}
	} else {
		if isAddOp {
			view.adminKeySets[keySetType] = view.adminKeySets[keySetType].Add(pubKey)
		} else {
			pos := view.adminKeySets[keySetType].Pos(pubKey)
			view.adminKeySets[keySetType] = view.adminKeySets[keySetType].Remove(pos)
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
			for i := 0; i < len(adminOutputs); i++ {
				isAddOp, keySetType, pubKey,
					keyID := txscript.ExtractAdminOpData(adminOutputs[i])
				isAddOp = !isAddOp
				view.applyAdminOp(isAddOp, keySetType, pubKey, keyID)
				// decrease lastKeyID counter, is an Add op is disconnected.
				if keySetType == btcec.WspKeySet && isAddOp {
					view.lastKeyID = keyID - 1
				}
			}
			// when an admin thread transaction is disconnected
			// we set the spent tx as new tip.
			threadId := rmgutil.ThreadID(threadInt)
			view.threadTips[threadId] = &tx.MsgTx().TxIn[0].PreviousOutPoint.Hash
		}
	}

	return nil
}

// NewKeyViewpoint returns a new empty key view.
func NewKeyViewpoint() *KeyViewpoint {
	return &KeyViewpoint{
		threadTips:   make(map[rmgutil.ThreadID]*chainhash.Hash),
		lastKeyID:    btcec.KeyID(0),
		totalSupply:  uint64(0),
		adminKeySets: make(map[btcec.KeySetType]btcec.PublicKeySet),
		wspKeyIdMap:  make(map[btcec.KeyID]*btcec.PublicKey),
	}
}
