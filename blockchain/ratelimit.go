package blockchain

// IsGenerationTrailingRateLimited determines if block generation is rate
// limited due to hitting a trailing rate limit.
func IsGenerationTrailingRateLimited(keyId uint32, prevKeyIds []uint32, maxTrailing int) bool {
	var trailingCount int
	for _, id := range prevKeyIds {
		if id != keyId {
			break
		}
		trailingCount++
		if trailingCount >= maxTrailing {
			return true
		}
	}
	return false
}

// IsGenerationShareRateLimited determines if block generation is rate
// limited due to a consumption of the permitted block share.
func IsGenerationShareRateLimited(keyId uint32, prevKeyIds []uint32, maxShare int) bool {
	var maxBlocks = len(prevKeyIds) * maxShare / 100
	// Exit early when the share limit is not meaningful
	if maxBlocks == 0 {
		return false
	}
	var blockCount int
	// Iterate through the ids, summing towards the mined blocks count
	for _, id := range prevKeyIds {
		if id == keyId {
			blockCount++
		}

		if blockCount > maxBlocks {
			return true
		}
	}
	return false
}
