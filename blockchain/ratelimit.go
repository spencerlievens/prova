package blockchain

import "github.com/bitgo/prova/wire"

// IsGenerationShareRateLimited determines if block generation is rate
// limited due to a consumption of the permitted block share.
func IsGenerationShareRateLimited(pubKey wire.BlockValidatingPubKey, prevPubKeys []wire.BlockValidatingPubKey, maxShare int) bool {
	var maxBlocks = len(prevPubKeys) * maxShare / 100
	// Exit early when the share limit is not meaningful
	if maxBlocks == 0 {
		return false
	}
	var blockCount int
	// Iterate through the ids, summing towards the mined blocks count
	for _, prevPubKey := range prevPubKeys {
		if prevPubKey == pubKey {
			blockCount++
		}

		if blockCount > maxBlocks {
			return true
		}
	}
	return false
}
