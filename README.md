# hats-zodiac

Hats Protocol-enabled [Zodiac](https://github.com/gnosis/zodiac) contracts

## Hats Signer Gate

A contract that grants multisig signing rights to addresses wearing a given Hat.

[HatsSignerGate.sol](./contracts/HatsSignerGate.sol) is a Zodiac module that grants multisig signing rights to addresses based on whether they are wearing the appropriate Hat(s).

It also serves as a Zodiac guard that ensures A) that only valid signers can execute transations, i.e. only signatures addresses currently wearing a valid signer hat count, and B) signers cannot execute transactions that...

1. remove the module from the multisig,
2. disconnect the guard from the multisig, or
3. change the multisig threshold

### MultiHats Signer Gate

[MultiHatsSignerGate.sol](./contracts/MultiHatsSignerGate.sol) is a modification of Hats Signer Gate that supports setting multiple Hats as a valid signer Hat.

### Hats Signer Gate Factory

[HatsSignerGateFactory](./contracts/HatsSignerGateFactory.sol) is a factory contract that deploys proxy instances of HatsSignerGate and MultiHatsSignerGate, either for an existing Safe or wired up to a new Safe deployed at the same time. It uses the [Zodiac module proxy factory](https://github.com/gnosis/zodiac/blob/master/contracts/factory/ModuleProxyFactory.sol) so that the deployments are tracked in the Zodiac subgraph.

### Recent Deployments

See [deployment parameters here](./script/DeployParams.json).

#### Beta 5

- Gnosis Chain (chain id #100)
  - singleton &mdash; `0xbD7090427331Cae6fC8b7f0C78d5f0fd3F2B3AFa`
  - factory &mdash; `0x805a6567eED224fBB62512085F9a106C8cD211f3`

#### Beta 4

> ⚠️ known bug in `removeSigner`

- Gnosis Chain (chain id #100)
  - singleton &mdash; `0x9b50AB91b3ffBcdd5d5Ed49eD70bf299434C955C`
  - factory &mdash; `0xC4b6005f48417D67b2a81c3E31672f4042D36361`
- Polygon (chain id #137)
  - singleton &mdash; `0xbecec728ff088b358d0b560529814a6132987e6a`
  - factory &mdash; `0x245e5b56c18b18ac2d72f94c5f7be1d52497a8ad`
