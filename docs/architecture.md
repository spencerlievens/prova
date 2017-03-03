# Prova Architecture

## Overview

Prova provides a platform for a digital asset issuer to create a distributed system for trading and storing representative tokens.

Prova provides tools for the root administrator of the platform:

1. Defensive consensus design to prevent token loss.
2. Limited ownership of tokens to approved holders.
3. Controls for participation in distributed timestamping.
4. Self-contained administration key and token supply management.

As a model and a technical basis for Prova, the long-running distributed [Bitcoin](https://www.bitcoin.org) block chain system is used as a basis: specifically the [btcd](https://github.com/btcsuite/btcd) implementation.

## Token Movement

Prova tokens are exchanged in **Prova transactions**, which contain output scripts defining a locking condition required for spending expressed as a smart contract script.

In Prova transactions, tokens may *only* be sent to an [n-of-m](https://en.wikipedia.org/wiki/Multisignature) key locked destination, where the majority of keys are specifically authorized. The minority remainder keys are standard public key hashes.

Even though the majority of the required signing keys are held by authoritative parties, it should be considered that the holders of the standard public key hashes are the intended owners of the tokens and in normal cases they will instigate token transfers.

### Account Service Providers

Authorized holders of tokens are provisioned with an **Account Service Provider (ASP) key**.

There are two intended use-cases for ASP keys:

1. Account transaction service providers who co-sign transactions based on security policies.
2. Account recovery service providers who can assist in key-loss situations.

Other than being provisioned, the account service provider keys act much like standard transaction signing keys.

As there are a limited number of ASP keys and they are intended for the most standard use, an integer called a **key id** is assigned to each key to use as a shorthand for the longer public key value.

## Block Validation

The movement of Prova tokens is timestamped using a [proof-of-work](http://hashcash.org/) block chain, as it is in the underlying model.  Every Prova node may sync the block chain to independently verify the ownership of tokens, and that is the standard mechanism for use.

Prova alters the proof-of-work system to prevent denial-of-service or double-spending attacks by introducing the concept of provisioned block generators with consensus limits.  Blocks must be signed with these provsioned **validate keys** to be considered valid.

### Chain Share Limits

The block chain design is suceptible to denial-of-service or double-spending attacks should an attack control a large ratio of solved blocks.  In the normal case the honest block generator majority will produce an eventually consistent version of the ledger, but given a sizeable enough minority or even a majority loss, these attacks become technically feasible.

To further safeguard against these issues, even provisioned validate keys are subject to consensus defined **share limits** that limit their allowed effective proof-of-work, or share of the blockchain.

## Asset Issuance

Asset tokens in Prova are not issued via coinbase rewards, instead they are allocated via **issue transactions**.

Issue transactions may only be signed by **issue keys** which are used to introduce and remove tokens from the system supply.

### Token Removal

Issue transactions are also used to remove tokens from the supply, however in this case the issue transaction must also include separate standard signatures authorizing the movement of the tokens being destroyed.

This prevents issue key holders from arbitrarily re-writing the token values, although they may add more tokens arbitrarily, taking value requires the cooperation of the normal token key holders.

## Admin Provisioning

Admin key provisioning, except for the starting set of genesis keys, occurs in special **admin transactions** that are included in the block chain.

All admin transactions are signed with any two keys from the set of applicable keys.  This follows the overall design pattern of requiring multiple signatures to encourage independent and redundant verification of immutable actions.

### Thread Operations

To prevent admin transactions from being reordered, admin transactions must spend an output from the previous admin transaction.  These special outputs are referred to as **admin threads**, key provisioning and token issue operations may only occur as extensions of a thread with an origin point in the genesis block.

