# What Is Prova?

Prova is an open source project implementing a single-asset, decentralized 
ledger with governance.

The Prova ledger is similar to Bitcoin's ledger and draws heavily from that 
project.  However, Prova differs from other ledger systems in that it offers:

 * Administrative asset issuance and destruction
 * Ability to operate in closed and open environments
 * Increased safety
    * All accounts are multi-signature
    * Impossible to send to invalid addresses

# Development Status

Prova is currently in active development and should be considered alpha 
quality.  Please join the
community to track releases, contribute, and get updates on development status.

# Design Goals

* Dynamic Asset Issuance

Asset issuance in Prova is done centrally.  The Asset Issuer's sole 
responsibility in Prova is to create and destroy the asset via newly introduced 
"admin transactions".  These transactions are public on the ledger and visible 
to all participants in the system.

* Safety

Prova takes extra precautions to ensure the digital asset cannot be easily 
lost.  All Prova Accounts are
equipped with a backup key and require at least two signatures for security. 
Further, it is not possible to
send to a non-recoverable Prova Account in the system, making it hard to lose 
control of an asset.

* Transparency

Like other blockchain technology, Prova aims to provide 100% transparency to 
all users of the system.
This includes transparency of administrative actions, so that all 
administrative actions within the chain
are publicly visible on the blockchain.

* Permissioned Participation

All participants in the system are authorized by the asset issuer.  This is 
done to ensure governance
can be maintained within the system via on-chain and off-chain rules.

* Proven Technology

The system was designed upon concepts already used in the most stable 
decentralized ledgers today.
In the future, it can be updated with new cryptographic feature support, 
consensus technology, and other
features, but for the initial version, a key decision was to use known, 
battle-tested algorithms.

Prova was created by BitGo as a fork of the btcd project, which is a reimplementation of Bitcoin Core in Go language.

# How Can I Use Prova?

Prova is designed for distributed asset exchange, 
where assets are fungible values backed by a root authority. 
As a root authority issuing assets, you would use Prova by tuning 
the configuration and starting a customized Prova network.

Prova is designed with flexibility in mind regarding the 
administrative features to suit a variety of uses.  For example, features 
such as provisioned block generation may be constrained to various degrees 
or left essentially unconstrained. 
