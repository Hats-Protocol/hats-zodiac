# Hats Signer Gate Super User

Hello! This repo contains a fork of [Hats Signer Gate](https://github.com/Hats-Protocol/hats-zodiac) to enable a hats-controlled multisig to be accountable to its admin hat(s). Currently this module is in early stages, so please use at your own risk. A DAO could potentially use these contracts to build on-chain committees: 

- assign elected members signer roles through hats
- transfer the grants budget to the safe
- allow committee members to independently dole out funds
- allow the DAO to clawback funds if need be
- allow the DAO to veto malicious/bad/self-serving transactions from the committee

The following contracts implement this functionality:

- HSGSuperMod
- HSGSuperFactory

## HSGSuperMod

This contract grants multisig signing rights to addresses wearing a given Hat, enabling on-chain organizations (such as DAOs) to revocably delegate constrained signing authority and responsibility to individuals, much like Hats Signer Gate, with some additional features: any admin hat can execute transactions on behalf of the safe (making it a “superuser”), and a special assignee (does not necessarily have to be a hats-wearer) can revoke safe transactions within an allotted period of time.

### Overview

### Zodiac Module

[HatsSignerGate.sol](https://github.com/Heph789/hsg-superuser/blob/dev/src/HSGSuperMod.sol) is a **Zodiac module** that...

1. Grants multisig signing rights to addresses based on whether they are wearing the appropriate Hat(s).
2. Removes signers who are no long valid (i.e. no longer wearing the signer Hat)
3. Manages the multisig threshold within the [owner](#contract-ownership) specified range as new signers are added or removed.
4. Allows any admin/top hat to transfer value on behalf of the safe.
5. Sends transactions through a [TimelockController](https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController), giving some assignee time to revoke transactions

### Zodiac Guard

Since Hat-wearing is dynamic — Hats can be programmatically revoked from wearers — this contract also services as a **Zodiac guard** to ensure that:

A) **Only valid signers can execute transactions**, i.e. only signatures made by accounts currently wearing a valid signer Hat count towards the threshold.

B) **Signers cannot execute transactions that remove the constraint in (A)**. Specifically, this contract guards against signers...

1. Removing the contract as a guard on the multisig
2. Removing the contract as a module on the multisig — or removing/changing/adding any other modules,
3. Changing the multisig threshold
4. Changing the multisig owners

> Warning
Protections against (3) and (4) above only hold if the Safe does not have any authority over the signer Hat(s). If it does — e.g. it wears an admin Hat of the signer Hat(s) or is an eligibility or toggle module on the signer Hat(s) — then in some cases the signers may be able to change the multisig threshold or owners.
> 
> 
> Proceed with caution if granting such authority to a Safe attached to HatsSignerGate.
> 

C) **Signers cannot execute transactions instantly.** All transactions must go through the TimelockController (and subsequently experience a delay) in order to execute.

### Contract Ownership

Hats Signer Gate uses the [HatsOwned](https://github.com/Hats-Protocol/hats-auth/) mix-in to manage ownership via a specified `ownerHat`.

The wearer of the `ownerHat` can make the following changes to Hats Signer Gate:

1. "Transfer" ownership to a new Hat by changing the `ownerHat`
2. Set the acceptable multisig threshold range by changing `minThreshold` and `targetThreshold`
3. Add other Zodiac modules to the multisig

> Note
Although these permissions are granted to the wearer of a defined `ownerHat`, the “superuser” ability to execute transactions on the safe’s behalf is currently granted to ***any*** tophat of the `signerHat`. In the future, this may be different to match the `ownerHat` paradigm.
> 

### HSGSuper Factory

[HSGSuperFactory](https://github.com/Heph789/hsg-superuser/blob/dev/src/HatsSignerGateFactory.sol) is a factory contract that enables users to deploy proxy instances of HSGSuperMod, either for an existing Safe or wired up to a new Safe deployed at the same time. It also deploys the corresponding TimelockController. It uses the [Zodiac module proxy factory](https://github.com/gnosis/zodiac/blob/master/contracts/factory/ModuleProxyFactory.sol) so that the deployments are tracked in the Zodiac subgraph.

### Deployments

Contracts aren’t yet deployed.
