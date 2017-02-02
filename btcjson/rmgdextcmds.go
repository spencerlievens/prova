// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// NOTE: This file is intended to house the RPC commands that are supported by
// an rmgd chain server.

package btcjson

// CreateRawAdminTransactionCmd defines the createrawadmintransaction
// JSON-RPC command.
type CreateRawAdminTransactionCmd struct {
	Txid    string  `json:"txid"`
	KeyType string  `json:"keytype"`
	Active  bool    `json:"active"`
	PubKey  string  `json:"pubkey"`
	KeyId   *uint32 `json:"keyid"`
}

// NewCreateRawAdminTransactionCmd returns a new instance which can be used
// to issue a createrawadmintransaction JSON-RPC command.
func NewCreateRawAdminTransactionCmd(txid string, keyType string, active bool,
	pubKey string, keyId *uint32) *CreateRawAdminTransactionCmd {

	return &CreateRawAdminTransactionCmd{
		Txid:    txid,
		KeyType: keyType,
		Active:  active,
		PubKey:  pubKey,
		KeyId:   keyId,
	}
}

// SetValidateKeysCmd defines the setvalidatekeys JSON-RPC command.
// This command is not a standard command, it is an extension for operating
// rmgd.
type SetValidateKeysCmd struct {
	PrivKeys []string
}

// NewSetValidateKeysCmd returns a new SetValidateKeysCmd which can
// be used to issue a setvalidatekeys JSON-RPC command.  This command is
// not a standard command. It is an extension for rmgd.
func NewSetValidateKeysCmd(privKeys []string) *SetValidateKeysCmd {
	return &SetValidateKeysCmd{
		PrivKeys: privKeys,
	}
}

func init() {
	// No special flags for commands in this file.
	flags := UsageFlag(0)

	MustRegisterCmd("setvalidatekeys", (*SetValidateKeysCmd)(nil), flags)
}
