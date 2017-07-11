// Copyright (c) 2014-2016 The btcsuite developers
// Copyright (c) 2016 The Zcash developers
// Copyright (c) 2017 BitGo
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"encoding/hex"
	"errors"
	"github.com/bitgo/prova/btcec"
	"github.com/bitgo/prova/chaincfg/chainhash"
	"github.com/bitgo/prova/wire"
	"math"
	"math/big"
	"time"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a block can
	// have for the main network.  It is the value 2^243 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 243), bigOne)

	// regressionPowLimit is the highest proof of work value a block
	// can have for the regression test network.
	regressionPowLimit = powLimitFromStr("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")

	// testNetPowLimit is the highest proof of work value a block can have
	// for the test network (version 3).
	testNetPowLimit = powLimitFromStr("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height uint32
	Hash   *chainhash.Hash
}

// DNSSeed identifies a DNS seed.
type DNSSeed struct {
	// Host defines the hostname of the seed.
	Host string

	// HasFiltering defines whether the seed supports filtering
	// by service flags (wire.ServiceFlag).
	HasFiltering bool
}

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []DNSSeed

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// AdminKeySets is the set of keys governing the chain state.
	AdminKeySets map[btcec.KeySetType]btcec.PublicKeySet

	// ASPKeyIdMap are the provisioned keyIDs and respective pubKeys
	ASPKeyIdMap btcec.KeyIdMap

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval uint32

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// Enforce current block version once network has
	// upgraded.  This is part of BIP0034.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has
	// upgraded.  This is part of BIP0034.
	BlockRejectNumRequired uint64

	// The number of nodes to check.  This is part of BIP0034.
	BlockUpgradeNumToCheck uint64

	// Mempool parameters
	RelayNonStdTxs bool

	// Address encoding magics
	ProvaAddrID  byte // First byte of an Prova address
	PrivateKeyID byte // First byte of a WIF private key

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32

	// Number of blocks for the moving window of difficulty adjustment.
	PowAveragingWindow int

	// Maximum downward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustDown int64

	// Maximum upward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustUp int64

	// Maximum blocks signed by a single validate key in averaging window.
	ChainWindowMaxBlocks int

	// Maximum fee allowed in a single transaction, in atoms.
	MaximumFeeAmount int64
}

// MaxActualTimespan returns a timespan with the down-dampening factor applied.
func (p Params) MaxActualTimespan() time.Duration {
	dampenPercentage := time.Duration(100 + p.PowMaxAdjustDown)
	return (p.AveragingWindowTimespan() * dampenPercentage) / 100
}

// MinActualTimespan returns a timespan with the up dampening factor applied.
func (p Params) MinActualTimespan() time.Duration {
	dampenPercentage := time.Duration(100 - p.PowMaxAdjustUp)
	return (p.AveragingWindowTimespan() * dampenPercentage) / 100
}

// MinValidateKeySetSize returns the minimum number of validate keys required
// to progress the chain, given the ChainWindowShareLimit.
func (p Params) MinValidateKeySetSize() int {
	powAveragingWindow := float64(p.PowAveragingWindow)
	chainWindowMaxBlocks := float64(p.ChainWindowMaxBlocks)
	return int(math.Ceil(powAveragingWindow / chainWindowMaxBlocks))
}

// AveragingWindowTimespan returns the difficulty timespan to be averaged over.
func (p Params) AveragingWindowTimespan() time.Duration {
	return time.Duration(p.PowAveragingWindow) * p.TargetTimePerBlock
}

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "7979",
	DNSSeeds: []DNSSeed{
		{"mainnet.rmgchain.info", false},
	},

	// Chain parameters
	GenesisBlock: &genesisBlock,
	GenesisHash:  &genesisHash,
	AdminKeySets: func() map[btcec.KeySetType]btcec.PublicKeySet {
		keySets := make(map[btcec.KeySetType]btcec.PublicKeySet)

		// Root keys
		keySets[btcec.RootKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"0351fe34a7869313aea20cd4f32d4c4c104a956e31914e52792edebb06ce706279",
			"0296c5ba078b550b405da30cca259df13a3f42f8b0130665980317730cc8cf8e83",
		)

		// Validate keys
		keySets[btcec.ValidateKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"031337c51889ee346ee194238a8a1d9cf56ea3943544b17ca9328947099128bc17",
			"031337e5f3edd3232bd0c1038416c113f0c0183abdc6d584ee33ac9b172bcba35c",
			"031337f5db2a5ce6f8c2a97fedfc5e051751dfc5a89247261804bb13ba306d1df9",
			"031337b5ac0e43f829f930e79494b587cc881e854f61198b5befa7ec188737058b",
			"02b523e29f24fce1f4360766c4f1a4d791b045a072379ff551f093d97a2b16e35a",
			"025ae36dc470129c7de919f3a77de74f00bf4179e7de838dd38f9452da24231337",
			"036b77b662372102e1519cdca417b00e37686a795d41fad336d48401bace331337",
			"029a66f9ece35927831e24e13096b6c7ccee4ca518c1ea2cad92e2c754a29b1750",
			"0323414c10a76e8c452077b2969d018150cc3341d25b6c4212e4bbcd574fab1337",
			"02f856a5edf891b36bda332d07a202f1a84c88a312a2a92adcb5fdc80d50ab1337",
			"021ffbdae400f3797ae57658592a930a4bad2030fcd4b98592338e71a441ab1337",
			"03d43eaf07c80eb23a3d25f57ba4de523f10914c50d683bf93071fd77eaaab1337",
			"032c37fdc2f45f60e836cb1827cc5100a9883ed5a04eee6ac29d534d68d9ab1337",
		)

		return keySets
	}(),
	ASPKeyIdMap: func() btcec.KeyIdMap {
		pubKey1, _ := btcec.ParsePubKey(hexToBytes("02bb4f88d0fa509aae16679dea651a5abda750515dc334c4b4f5cc271885535db9"), btcec.S256())
		pubKey2, _ := btcec.ParsePubKey(hexToBytes("03afc00846b67084f30bec1752a3e4ba32c2831f2aeb27911225162c8c95481d9e"), btcec.S256())
		return map[btcec.KeyID]*btcec.PublicKey{btcec.KeyID(1): pubKey1, btcec.KeyID(2): pubKey2}
	}(),
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1f07ffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimePerBlock:       time.Second * 150, // 2.5 minutes
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: false,

	// Address encoding magics
	PrivateKeyID: 0x80, // starts with 5 (uncompressed) or K (compressed)
	ProvaAddrID:  0x33, // starts with G

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,

	// Number of blocks for the moving window of difficulty adjustment.
	PowAveragingWindow: 31,

	// Maximum downward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustDown: 32,

	// Maximum upward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustUp: 16,

	// Maximum blocks signed by a single validate key in averaging window.
	ChainWindowMaxBlocks: 3,

	// Maximum fee allowed in a single transaction, in atoms.
	MaximumFeeAmount: 5000000,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network.
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.RegNet,
	DefaultPort: "18989",
	DNSSeeds:    []DNSSeed{},

	// Chain parameters
	GenesisBlock: &regTestGenesisBlock,
	GenesisHash:  &regTestGenesisHash,
	AdminKeySets: func() map[btcec.KeySetType]btcec.PublicKeySet {
		keySets := make(map[btcec.KeySetType]btcec.PublicKeySet)

		// Root keys
		keySets[btcec.RootKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1", // priv eaf02ca348c524e6392655ba4d29603cd1a7347d9d65cfe93ce1ebffdca22694
			"038ef4a121bcaf1b1f175557a12896f8bc93b095e84817f90e9a901cd2113a8202", // priv 2b8c52b77b327c755b9b375500d3f4b2da9b0a1ff65f6891d311fe94295bc26a
		)

		// Provision Keys
		keySets[btcec.ProvisionKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"0248b3b4e579444e6b7cc414510109316c4c9ba7a2a46f50f8dcbb273efb1337ab", // priv f954b388f5db3a1d2915cda434206d791b47cf3d4e78cc32fbeb77ea25d20d7d
			"02ef86c70ae6afd2dd2f0efb07ea59789c27a1bf43f687b35dac435b539e1337ab", // priv 627f6f1d5d8f38bd60b6aaea2f74c72917deffcc2a5a64f67d3e0a28a2d711c1
		)

		// Issue Keys
		keySets[btcec.IssueKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"02ef7739dc67d38f2804a9c0aa1add89a992ced5f37e580ea8ccbb5742391337ab", // priv 3f9222ab4d30b1795941d9815e5833a4da70cb04bff59a5fd2ddc4641e58607e
			"021126d3d6158cf4f47eb2e08d12e9fa46d8da7b7e401220260bdc46446f1337ab", // priv 0a40defde0e49e1f78edb9cea5c499f704fabc140d6fd1a4df8405365e2e4f0f
		)

		// Validate keys
		keySets[btcec.ValidateKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"035f5103852bd7d9c9c28e44caf1f7188941e16295062ca4c89928a8ccff993cd3", // TODO(prova) add priv
			"0265de49399e78020026219492e2a6e1a41e93591b87220ae8a2f3ebf3473dbeef", // TODO(prova) add priv
			"039cb94c99c4700918250c40fa35b7fa0a75a967c9366aa19b8fc354373368beef", // TODO(prova) add priv
			"031337ab09070254638075c7b59643dce2d60c5260bf5841d2f8cc6f75f6790d4e", // TODO(prova) add priv
			"03133752072c8bc132679655c671b7953c2edabc575f42d60fa2e4caac09770061", // d36c82406d3c77ebc342aaa16f24a985fbfe63c75e6fd2afeffa1ba69632d252
			"02ab82d1531552c5b67e528047542ff9a2550ee4df7a88d67037754069db0541f9", // 05fa7a36092cc7accc8008365fd8d07229c794be2a4e9361c662b5cae9492fa3
			"02ab8264fdb09480d07b4db2d25db28065d51ea2950da89b7366d13b3c7be25e92", // a3262a6f506e4bfd4bc5b0708b2162e755410c8670e38c53928eb093ece2d37e
			"02ab829a899bb14365e45099062b9a9543e8c51d4ace1ddfb7ef52320bb6dabbdd", // 041bf76c17185bcddbbb5d40122d04528fbe6c68f488c16a4e85711410134b5e
			"02ab8201f1834926a5388ca4157f56008238b84fdcd0bd208647151ef617ac49ed", // 224688827325203eb53d0ec0f044b72312c8e11fc4fdada7b91416e7b54939d5
			"02ab821a995287881d383718476bf2305dee70174a4727688070701490c526061b", // c37e338bebe77d1ca77438ad7a382dc97c28703d793c732d88348eb5f26f9732
			"02ab82faed27170fc9c2dc3ab57ebba5c0d2649b6044011c77ca4b27aef05c6e07", // 6d4a926fec187ee0a0b0395cadb39360687b8416809c21ab32490e944784d6a3
		)

		return keySets
	}(),
	ASPKeyIdMap: func() btcec.KeyIdMap {
		pubKey1, _ := btcec.ParsePubKey(hexToBytes("025ceeba2ab4a635df2c0301a3d773da06ac5a18a7c3e0d09a795d7e57d233edf1"), btcec.S256())
		pubKey2, _ := btcec.ParsePubKey(hexToBytes("038ef4a121bcaf1b1f175557a12896f8bc93b095e84817f90e9a901cd2113a8202"), btcec.S256())
		return map[btcec.KeyID]*btcec.PublicKey{btcec.KeyID(1): pubKey1, btcec.KeyID(2): pubKey2}
	}(),
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x200f0f0f,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 150,
	TargetTimePerBlock:       time.Minute, // 1 minute
	GenerateSupported:        true,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	ProvaAddrID:  0x58, // starts with T
	PrivateKeyID: 0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,

	// Number of blocks for the moving window of difficulty adjustment
	PowAveragingWindow: 31,

	// Maximum downward adjustment in pow difficulty, as a percentage
	PowMaxAdjustDown: 32,

	// Maximum upward adjustment in pow difficulty, as a percentage
	PowMaxAdjustUp: 16,

	// Maximum fee allowed in a single transaction, in atoms.
	MaximumFeeAmount: 5000000,
}

// TestNetParams defines the network parameters for the test network.
var TestNetParams = Params{
	Name:        "testnet",
	Net:         wire.TestNet,
	DefaultPort: "17979",
	DNSSeeds: []DNSSeed{
		{"testnet.rmgchain.info", false},
	},

	// Chain parameters
	GenesisBlock: &testNetGenesisBlock,
	GenesisHash:  &testNetGenesisHash,
	AdminKeySets: func() map[btcec.KeySetType]btcec.PublicKeySet {
		keySets := make(map[btcec.KeySetType]btcec.PublicKeySet)

		// Issue keys
		keySets[btcec.IssueKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"029cd0486fd4a5b260f956e1b16db17cd0e2f8914054b30eddda17950af7033855",
			"034d3083c7ad8537d5397fbb65aa6794e5db24d8c4ed3a1f4e12285a447c83ffc7",
		)

		// Provision keys
		keySets[btcec.ProvisionKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"029cd0486fd4a5b260f956e1b16db17cd0e2f8914054b30eddda17950af7033855",
			"0307051d31f87efb84839115c09e6160cf7b9ac210860202792e1cea7bd32a7051",
		)

		// Root keys
		keySets[btcec.RootKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"023cc2d11d97728d6d69d1d296513e12e0439c225b612f1a24e5d3b3a333d058aa",
			"029cd0486fd4a5b260f956e1b16db17cd0e2f8914054b30eddda17950af7033855",
			"03ecf113dd8476ab79a64c7b8eeaf30999744777ed8b31a91387fd76b0d798d9fd",
			"03ce7f7ee8e5e01de741649b69655f168526ebb476e1fb8f250a825f824cf7b63e",
		)

		// Validate keys
		keySets[btcec.ValidateKeySet], _ = btcec.ParsePubKeySet(btcec.S256(),
			"031337b4828f61541f003634ebe6c55a9cca4d13c7fec34f2698939272a76b15b0",
			"031337e5bbe1b43b283ab56d5ceb64c159b0b5abd5ab58edd7d0ccad5360a23130",
			"031337b35bb33a8bfa9c190f617e139efef3d307bb1a981f17fd0ea6a42010f5ae",
			"031337eeb34fd8eb0af9e171c448a66ea632311cfe8316f7aed49b954ac6c054f7",
			"0372d56e2288fdd17a0975baa9607d5143f4b330b801142db16405ec961dab1337",
			"02615e88cd09e731816926cd7f16caad87b6b7ae54ef440d3ffb7d935eedab1337",
			"03d9e4d1bccd8efae3f74ae57258dd41c3c250e8b3806e7891a0a4d07fc3ab1337",
			"031337b1b33037ad401a189389f65bda1f9abd1497c956834c99213f0bd2d931ed",
			"031337ef04ae0d9b7f46f11889bbb0362d8477661a8ec5fabbaf85e9beb24eef20",
			"031337a189ad45659f2eebd521c43775e3d6c69e1c25b9b3498909e95c5d2da3b6",
			"031337e3ab1c86cbb6d67208b273098df863d1f3080947602d894cae4bc2d19d5c",
		)

		return keySets
	}(),
	ASPKeyIdMap: func() btcec.KeyIdMap {
		pubKey1, _ := btcec.ParsePubKey(hexToBytes("036bcc8bc2af28edd3b1b8d25baefa0f06dd4fc243da0587268b5899d5538fc8a6"), btcec.S256())
		pubKey2, _ := btcec.ParsePubKey(hexToBytes("021497b39f2f32eeaa1083c52ee265d0fad85338fb82bf8c0ae4a1dbe746e4a45b"), btcec.S256())
		return map[btcec.KeyID]*btcec.PublicKey{btcec.KeyID(1): pubKey1, btcec.KeyID(2): pubKey2}
	}(),
	PowLimit:                 testNetPowLimit,
	PowLimitBits:             0x2007ffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimePerBlock:       time.Second * 150, // 2.5 minutes
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PrivateKeyID: 0xef, // starts with 9 (uncompressed) or c (compressed)
	ProvaAddrID:  0x58, // starts with T

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,

	// Number of blocks for the moving window of difficulty adjustment.
	PowAveragingWindow: 31,

	// Maximum downward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustDown: 64,

	// Maximum upward adjustment in pow difficulty, as a percentage.
	PowMaxAdjustUp: 64,

	// Maximum blocks signed by a single validate key in averaging window.
	ChainWindowMaxBlocks: 3,

	// Maximum fee allowed in a single transaction, in atoms.
	MaximumFeeAmount: 5000000,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "10079",
	DNSSeeds:    []DNSSeed{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimePerBlock:       time.Second * 150, // 2.5 minutes
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PrivateKeyID: 0x64, // starts with 4 (uncompressed) or F (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s

	// Number of blocks for the moving window of difficulty adjustment
	PowAveragingWindow: 31,

	// Maximum downward adjustment in pow difficulty, as a percentage
	PowMaxAdjustDown: 32,

	// Maximum upward adjustment in pow difficulty, as a percentage
	PowMaxAdjustUp: 16,

	// Maximum blocks signed by a single validate key in averaging window.
	ChainWindowMaxBlocks: 3,

	// Maximum fee allowed in a single transaction, in atoms.
	MaximumFeeAmount: 5000000,
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")
)

var (
	registeredNets    = make(map[wire.BitcoinNet]struct{})
	pubKeyHashAddrIDs = make(map[byte]struct{})
	scriptHashAddrIDs = make(map[byte]struct{})
	provaAddrIDs      = make(map[byte]struct{})
	hdPrivToPubKeyIDs = make(map[[4]byte][]byte)
)

// String returns the hostname of the DNS seed in human-readable form.
func (d DNSSeed) String() string {
	return d.Host
}

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	if params.ProvaAddrID != 0 {
		provaAddrIDs[params.ProvaAddrID] = struct{}{}
	}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// IsProvaAddrID returns whether the id is an identifier known to prefix a
// standard Prova address on any default or registered network.  This is
// used when decoding an address string into a specific address type.
func IsProvaAddrID(id byte) bool {
	_, ok := provaAddrIDs[id]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

// powLimitFromStr returns a pow limit based on a difficulty hex value.
func powLimitFromStr(hexStr string) *big.Int {
	limit := big.NewInt(0)
	limit.SetString(hexStr, 16)
	return limit
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNetParams)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
}
