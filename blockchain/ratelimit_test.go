package blockchain

import (
	"encoding/hex"
	"testing"

	"github.com/bitgo/rmgd/btcec"
	"github.com/bitgo/rmgd/wire"
)

// TestIsGenerationTrailingRateLimited tests that generation is rate limited
// from the perspective of the maximal number of consecutive blocks.
func TestIsGenerationTrailingRateLimited(t *testing.T) {
	keyBytes, _ := hex.DecodeString("4015289a228658047520f0d0abe7ad49abc77f6be0be63b36b94b83c2d1fd977")
	key, _ := btcec.PrivKeyFromBytes(btcec.S256(), keyBytes)
	var pubKey wire.BlockValidatingPubKey
	copy(pubKey[:wire.BlockValidatingPubKeySize], key.PubKey().SerializeCompressed()[:wire.BlockValidatingPubKeySize])
	chain := make([]wire.BlockValidatingPubKey, 0)
	limit := 2
	whenGenerationStarts := IsGenerationTrailingRateLimited(pubKey, chain, limit)
	chain = append([]wire.BlockValidatingPubKey{pubKey}, chain...)
	whenUnderLimit := IsGenerationTrailingRateLimited(pubKey, chain, limit)
	chain = append([]wire.BlockValidatingPubKey{pubKey}, chain...)
	whenAtLimit := IsGenerationTrailingRateLimited(pubKey, chain, limit)
	chain = append([]wire.BlockValidatingPubKey{pubKey}, chain...)
	chain = append([]wire.BlockValidatingPubKey{pubKey}, chain...)
	whenNoLimit := IsGenerationTrailingRateLimited(pubKey, chain, 0)
	isRateLimited := true

	if whenGenerationStarts == isRateLimited {
		t.Fatalf("Expected no rate limit for chain start")
	}

	if whenUnderLimit == isRateLimited {
		t.Fatalf("Expected no rate limit for minimal trailing")
	}

	if whenAtLimit == !isRateLimited {
		t.Fatalf("Expected rate limiting for excessive trailing")
	}

	if whenNoLimit == isRateLimited {
		t.Fatalf("Expected no limiting when no limit is specified")
	}
}

// TestIsGenerationShareRateLimited tests that generation is rate limited
// below a ratio of total blocks.
func TestIsGenerationShareRateLimited(t *testing.T) {
	keyBytes0, _ := hex.DecodeString("4015289a228658047520f0d0abe7ad49abc77f6be0be63b36b94b83c2d1fd977")
	keyBytes1, _ := hex.DecodeString("9ade85268e57b7c97af9f84e0d5d96138eae2b1d7ae96c5ab849f58551ab9147")
	key0, _ := btcec.PrivKeyFromBytes(btcec.S256(), keyBytes0)
	key1, _ := btcec.PrivKeyFromBytes(btcec.S256(), keyBytes1)
	var pubKey0 wire.BlockValidatingPubKey
	var pubKey1 wire.BlockValidatingPubKey
	copy(pubKey0[:wire.BlockValidatingPubKeySize], key0.PubKey().SerializeCompressed()[:wire.BlockValidatingPubKeySize])
	copy(pubKey1[:wire.BlockValidatingPubKeySize], key1.PubKey().SerializeCompressed()[:wire.BlockValidatingPubKeySize])

	chain := make([]wire.BlockValidatingPubKey, 0)
	share := 50

	whenGenerationStarts := IsGenerationShareRateLimited(pubKey0, chain, share)

	chain = append([]wire.BlockValidatingPubKey{pubKey0}, chain...)

	whenUnderLimit := IsGenerationShareRateLimited(pubKey0, chain, share)

	chain = append([]wire.BlockValidatingPubKey{pubKey0}, chain...)

	whenAtLimit := IsGenerationShareRateLimited(pubKey0, chain, share)

	chain = append([]wire.BlockValidatingPubKey{pubKey1}, chain...)

	whenMiningWithOther := IsGenerationShareRateLimited(pubKey0, chain, share)

	rateLimited := true

	if whenGenerationStarts == rateLimited {
		t.Fatalf("Expected no rate limit when generation starts")
	}

	if whenUnderLimit == rateLimited {
		t.Fatalf("Expected no rate limit while under limit")
	}

	if whenAtLimit == !rateLimited {
		t.Fatalf("Expected limiting when share is reached")
	}

	if whenMiningWithOther == !rateLimited {
		t.Fatalf("Expected no rate limit when mining is diverse")
	}
}
