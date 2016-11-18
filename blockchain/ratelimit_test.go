package blockchain

import "testing"

// TestIsGenerationTrailingRateLimited tests that generation is rate limited
// from the perspective of the maximal number of consecutive blocks.
func TestIsGenerationTrailingRateLimited(t *testing.T) {
	chain := make([]uint32, 0)
	id := uint32(1)
	limit := 2

	whenGenerationStarts := IsGenerationTrailingRateLimited(id, chain, limit)

	chain = append([]uint32{id}, chain...)

	whenUnderLimit := IsGenerationTrailingRateLimited(id, chain, limit)

	chain = append([]uint32{id}, chain...)

	whenAtLimit := IsGenerationTrailingRateLimited(id, chain, limit)

	whenNoLimit := IsGenerationShareRateLimited(id, chain, 0)

	rateLimited := true

	if whenGenerationStarts == rateLimited {
		t.Fatalf("Expected no rate limit for chain start")
	}

	if whenUnderLimit == rateLimited {
		t.Fatalf("Expected no rate limit for minimal trailing")
	}

	if whenAtLimit == !rateLimited {
		t.Fatalf("Expected rate limiting for excessive trailing")
	}

	if whenNoLimit == rateLimited {
		t.Fatalf("Expected no limiting when no limit is specified")
	}
}

// TestIsGenerationShareRateLimited tests that generation is rate limited
// below a ratio of total blocks.
func TestIsGenerationShareRateLimited(t *testing.T) {
	chain := make([]uint32, 0)
	id := uint32(1)
	id2 := uint32(2)
	share := 50

	whenGenerationStarts := IsGenerationShareRateLimited(id, chain, share)

	chain = append([]uint32{id}, chain...)

	whenUnderLimit := IsGenerationShareRateLimited(id, chain, share)

	chain = append([]uint32{id}, chain...)

	whenAtLimit := IsGenerationShareRateLimited(id, chain, share)

	chain = append([]uint32{id2}, chain...)

	whenMiningWithOther := IsGenerationShareRateLimited(id, chain, share)

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
