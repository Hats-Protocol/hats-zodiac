# Hats Signer Gate

This repo holds a [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol)-enabled [Zodiac](https://github.com/gnosis/zodiac) contract called Hats Signer Gate (HSG).

## Hats Signer Gate v2

A contract that grants multisig signing rights to addresses wearing a given hats, enabling on-chain organizations (such as DAOs) to revocably delegate to individuals constrained authority and responsibility to operate an account (i.e. a Safe) owned by the organization.

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
4. Add other Hats as valid signer Hats

### Deploying New Instances

Instances of HSG can be created via the [Zodiac module proxy factory](https://github.com/gnosisguild/zodiac/blob/18b7575bb342424537883f7ebe0a94cd7f3ec4f6/contracts/factory/ModuleProxyFactory.sol).

Instances can be created for an existing Safe by passing the Safe address on initialization, or for a new Safe to be deployed from within HSG's initialization.

### Security Audits

This project has received the following security audits. See the [audits directory](./audits/) for the detailed reports.

| Auditor | Report Date | Commit Hash | Notes |
| --- | --- | --- | --- |
| Trust Security | Feb 23, 2023 | [b9b7fcf](https://github.com/Hats-Protocol/hats-zodiac/commit/b9b7fcf22fd5cbb98c7d93dead590e80bf9c780a) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |
| Sherlock | May 3, 2023 | [9455c0](https://github.com/Hats-Protocol/hats-zodiac/commit/9455cc0957762f5dbbd8e62063d970199109b977) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |

### Recent Deployments

See [Releases](https://github.com/Hats-Protocol/hats-zodiac/releases) for deployments. Specific deployment parameters are [stored here](./script/DeployParams.json).
