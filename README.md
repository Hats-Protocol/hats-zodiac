# hats-zodiac

This repo holds several [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol)-enabled [Zodiac](https://github.com/gnosis/zodiac) contracts. Currently, this repo contains the following, referred to collectively as Hats Signer Gate (HSG):

- [Hats Signer Gate](#hats-signer-gate)
- [Multi-Hats Signer Gate](#multi-hats-signer-gate)
- [Hats Signer Gate Factory](#hats-signer-gate-factory)

## Hats Signer Gate

A contract that grants multisig signing rights to addresses wearing a given Hat, enabling on-chain organizations (such as DAOs) to revocably delegate constrained signing authority and responsibility to individuals.

### Overview

#### Zodiac Module

[HatsSignerGate.sol](./src/HatsSignerGate.sol) is a **Zodiac module** that...

1. Grants multisig signing rights to addresses based on whether they are wearing the appropriate Hat(s).
2. Removes signers who are no long valid (i.e. no longer wearing the signer Hat)
3. Manages the multisig threshold within the [owner](#contract-ownership)-specified range as new signers are added or removed.

#### Zodiac Guard

Since Hat-wearing is dynamic — Hats can be programmatically revoked from wearers — this contract also services as a **Zodiac guard** to ensure that:

A) **Only valid signers can execute transactions**, i.e. only signatures made by accounts currently wearing a valid signer Hat count towards the threshold.

B) **Signers cannot execute transactions that remove the constraint in (A)**. Specifically, this contract guards against signers...

1. Removing the contract as a guard on the multisig
2. Removing the contract as a module on the multisig — or removing/changing/adding any other modules,
3. Changing the multisig threshold
4. Changing the multisig owners

> **Warning**
> Protections against (3) and (4) above only hold if the Safe does not have any authority over the signer Hat(s). If it does — e.g. it wears an admin Hat of the signer Hat(s) or is an eligibility or toggle module on the signer Hat(s) — then in some cases the signers may be able to change the multisig threshold or owners.
>
> Proceed with caution if granting such authority to a Safe attached to HatsSignerGate.

### Contract Ownership

Hats Signer Gate uses the [HatsOwned](https://github.com/Hats-Protocol/hats-auth/) mix-in to manage ownership via a specified `ownerHat`.

The wearer of the `ownerHat` can make the following changes to Hats Signer Gate:

1. "Transfer" ownership to a new Hat by changing the `ownerHat`
2. Set the acceptable multisig threshold range by changing `minThreshold` and `targetThreshold`
3. Add other Zodiac modules to the multisig
4. In [Multi-Hats Signer Gate](#multi-hats-signer-gate), add other Hats as valid signer Hats

### Multi-Hats Signer Gate

[MultiHatsSignerGate.sol](./src/MultiHatsSignerGate.sol) is a modification of Hats Signer Gate that supports setting multiple Hats as valid signer Hats.

### Hats Signer Gate Factory

[HatsSignerGateFactory](./src/HatsSignerGateFactory.sol) is a factory contract that enables users to deploy proxy instances of HatsSignerGate and MultiHatsSignerGate, either for an existing Safe or wired up to a new Safe deployed at the same time. It uses the [Zodiac module proxy factory](https://github.com/gnosis/zodiac/blob/master/contracts/factory/ModuleProxyFactory.sol) so that the deployments are tracked in the Zodiac subgraph.

### Security Audits

This project has received the following security audits. See the [audits directory](./audits/) for the detailed reports.

| Auditor | Report Date | Commit Hash | Notes |
| --- | --- | --- | --- |
| Trust Security | Feb 23, 2023 | [b9b7fcf](https://github.com/Hats-Protocol/hats-zodiac/commit/b9b7fcf22fd5cbb98c7d93dead590e80bf9c780a) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |
| Sherlock | May 3, 2023 | [9455c0](https://github.com/Hats-Protocol/hats-zodiac/commit/9455cc0957762f5dbbd8e62063d970199109b977) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |

### Recent Deployments

See [Releases](https://github.com/Hats-Protocol/hats-zodiac/releases) for deployments. Specific deployment parameters are [stored here](./script/DeployParams.json).
