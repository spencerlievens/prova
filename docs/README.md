# RMG Chain Design

## Summary

The RMG blockchain is a Bitcoin-derived blockchain, custom-designed for the use case of safely digitizing and transacting a representation of an underlying physical asset, in this case gold vaulted by [The Royal Mint](http://www.royalmint.com/). Its reference implementation is based on a fork of [btcd](https://github.com/btcsuite/btcd), which is written in Go (still a work in progress).

## Design Docs

[Block Format](design/block_format.md)

[Safe Multi-Sig Addresses](design/safe_multisig.md)

[Administrative Transactions](design/admin.md)

[Validator Rate-Limiting](design/rate_limiter.md)

[Proof-of-Work Hash Function Exploration](design/hashfuncs.md)

## Practical Info

[Install Guide](install-guide.md)

[Admin RPC API](admin-api.md)

[Example Raw Transactions](https://gist.github.com/alexbosworth/3f5c959c828090c7e92a7d694181a57c)