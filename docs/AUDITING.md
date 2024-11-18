# HatsSignerGate v2 for auditors

## Introduction: Hats Protocol

[Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) is a protocol for creating and managing onchain roles, aka “hats.” Organizations typically use hats to represent tasks, jobs, workstreams, teams, departments, etc.

Hats Protocol uses a singleton (multitenant) architecture. All organizations' roles are stored in the same contract. Each organization has full control over its own roles, and no control over the roles of another organization unless explicitly granted.

Hats are onchain objects, exposed to other contracts and offchain consumers as ERC1155 tokens. The id of a given hat is its token id.

Within a given organization, hats form in a tree structure, with parent-child relationships. With the exception of the root of the tree (the “top hat”), hats are not transferable by the owner of the hat token (the “wearer” of the hat).

Every hat has several key properties:

- An admin (its parent hat, a uint), which can create new child hats, modify the properties of its children, and mint its children to accounts (“wearers”). Admins can exercise these powers transitively for all children, children’s children, etc.
- An eligibility module (address), which can a) determine which accounts are allowed to wear the hat, and b) revoke the hat from existing wearers. Eligibility modules can push such status changes to the protocol, or they can implement the IHatsEligibility interface to enable the protocol to pull wearer status from their own state.
- A toggle module (address), which can deactivate the hat. Toggle modules can push such status changes to the protocol, or they can implement the IHatsToggle interface to enable the protocol to pull hat status from their own state.
A max supply (uint32), which is the maximum number of accounts that can wear the hat.
- Mutability (bool), which determines whether or not the admin can change any of these properties. If a hat is immutable, its admins can mint it to new wearers, the eligibility module can revoke it from current wearers, and the toggle module can deactivate it, but nothing else can change.
- A details/metadata field (string)
- An image uri field (string)

Hats can be revoked in two ways:

1. “Statically,” resulting in the wearer’s hat token being fully burned (burn event emitted). This occurs when an eligibility module pushes an update to the protocol, as described above.
2. “Dynamically,” resulting in the wearer’s balance of the hat going to 0 but without a full burn of the token (no burn event emitted). This occurs when the protocol pulls either a) “ineligible” status from a compliant eligibility module, or b) “inactive” status from a compliant toggle module.
   - Dynamic revocation is made possible by staticcalls (the “pulls”) out to the hat’s eligibility and toggle modules from within the ERC1155.balanceOf function.
   - If a hat has been dynamically revoked, any account can poke the protocol to fully burn the token (burn event emitted), but this is not required for the revocation to count. The source of truth is always the balance returned by ERC1155.balanceOf.

A given ethereum account can wear many hats, but the protocol enforces that a given account cannot have more than 1 copy of a given hat (ie no account’s balance of a given hat must always be 0 or 1).

## Attaching Permissions to Hats

One of the foundational use cases of hats is attaching permissions. Much like in role-based access control systems, multiple permissions can be attached to hats to make permission management easier and more efficient.

Attaching permissions to hats works via token gating (this is one reason Hats implements the ERC1155 interface), and can include both offchain permissions (via standard token-gating techniques leveraging Sign In With Ethereum) and onchain permissions. Onchain permissioning via hats looks a lot like standard address-based permissioning in smart contracts functions (such as in OZ.Ownable, OZ.AccessControl, etc), but instead of checking whether msg.sender is authorized within the same contract, a hat-permission function checks whether msg.sender has a balance of the specific hat token. Note that this means that authorization can change without needing to interact with the target contract.

## HatsSignerGate

HatsSignerGate (HSG) is an adapter that enables organizations to attach Safe multisig signing permissions to hats. Wearers of a specified hat can become signers on an HSG-gated Safe, and only wearers of the specified hat can provide valid signatures when attempting to execute a multisig transaction. HSG accomplishes the former as a module enabled on the Safe, and the latter as a guard set on the Safe.

It is designed to enable organizations to delegate operations of a Safe and the assets therein to a set of operators (“signers”) while retaining ultimate ownership of the Safe account, including who the signers are.
Security
From a security perspective, the ideal way to build such a product would be to fork the Safe contract and insert out hat-based signer management logic natively (or build an entirely new contract). Since Safe was originally designed to be controlled by a sovereign set of owners rather than a delegated set of operators, the signers on a Safe have many ways to control the Safe’s properties. In order to ensure that the Safe remains under the control of the delegating organization, there is a lot of surface area to cover.

However, the Safe ecosystem has such strong network effects that it is worth the extra effort. The organizations that use Hats Protocol specifically want delegated Safes, not some other type of account. And they want to use the Safe-compatible apps they are already familiar with, like Safe’s own UI or others like Den.

Therefore, the primary objective HatsSignerGate seeks to accomplish is to lock down a Safe so that its signers can use the Safe to manage its assets but not change any of its properties. Of utmost importance is that the signers not be able to jailbreak those constraints. Specifically, the signers should not be able to:

- Add or remove signers
- Change the threshold
- Disable HSG as a module on the Safe
- Remove HSG as a guard on the Safe
- Do anything else that would allow them to do 1-4. This includes:
  - Enabling other modules on the Safe
  - Executing delegatecalls to contracts that directly update the Safe's state in such a way that cannot be detected by HSG's guard functionality
  - Changing the Safe singleton that provides the logic to the Safe's proxy
  - Changing the fallback handler

> **Warning**
> These limitations must not be violated.

## Tradeoffs and Limitations of v1

The contract that you are currently auditing is HSG v2. HSG v1 was developed and audited ~18 months ago. Since then, we have learned a lot about how organizations want to use it, and our understanding of the full surface area of the Safe contract has advanced. As a result, a number of limitations and sub-optimalities with v1 have surfaced which have driven us to develop v2.

### A) Incompatibility with other Safe modules and guards

Perhaps the biggest thing we learned from our users is that they want to use HSG with additional modules and guards such as UMA’s oSnap module, Decent’s Fractal module, OZ’s timelock guard, Gnosis Guild’s Roles Mod, Connext’s Crosschain module, etc.

But in v1 we explicitly disabled additional modules because modules have full control over the Safe. If the signers were allowed to add a module of their choosing, they would have unmediated control over the Safe. They could change anything, including detaching HSG, which is exactly what we want to protect against.

### B) Delegatecalls

One of the most difficult elements of Safe to handle correctly is delegatecall. In practice, Safe makes heavy use of delegatecalls to enable common use cases like batching multiple actions and transactions, ie by delegatecalling their MultiSend library. That library does not present a security issue, but the need to allow delegatecalls does.

If the signers were to execute a delegatecall to a contract with certain logic, they could directly update the Safe’s state, bypassing the typical Safe functions to do so. This is an issue because two of the critical types of Safe state changes we want to avoid — owners and modules — are mappings and therefore infeasible to explicitly check onchain. For example, a malicious delegatecalled contract could change the value for an address’s key in the owner mapping such that Safe’s logic would treat the address as a valid owner but not retrieve it as part of the owner linked list. The same issue exists for modules.

### C) Updating the proxy to a malicious Safe singleton

Also due to the need to allow arbitrary delegatecalls, the signers could update the Safe proxy to point to a different Safe singleton (aka “master copy” or “implementation”) contract that exposes sensitive functionality to an attacker.

### D) Setting a malicious fallback handler

Safe has a modular fallback concept that enables extensions to the Safe’s functionality via setting a fallback handler contract. The fallback handler deployed with new Safes by default, for example, is where ERC1271 compliance is implemented. In regular usage, the Safe itself (ie the signers or a module) can update the fallback handler to an arbitrary contract address.

But if the signers (or a rogue module; see A) did this, they could gain the same unmediated access to Safe state as adding a module.

### E) Sub-optimal gas overhead

Some of the techniques we used to implement our desired logic and protections in v1 were not ideal, leading to what we now think is an extra 20k-40k gas cost for every transaction executed by signers.

This is not that big of a deal on L2s, but on L1 it imposes meaningful costs on users and limits the potential market for what we’re building.

### F) Valid threshold legibility

HSG enables an organization to control the decision model for the delegated account. In other words, in addition to controlling who the signers are, HSG controls how many signers are needed to execute a transaction, ie the multisig threshold N. Because the Safe only validates N signatures regardless of how many are included in the signature bytes array of a multisig transaction, HSG needs to keep the Safe threshold up to date in accordance with the number of presently hat-wearing signers. But since hats can be revoked dynamically (see the Hats Protocol intro above), HSG is not always aware of such a change. This means that HSG needs to check whether each signer is still wearing the hat whenever it tries to update the Safe’s threshold, contributing to some of the gas overhead (see (E)) and otherwise increasing complexity.

### G) Inability to remove HSG

To give signers some form of credible expectations, we didn’t allow orgs to detach HSG from the Safe. This was a mistake, since it added significant friction when deciding whether to try HSG in the first place.

### Implications for v2

For (A), we need to find a solution to this problem. Part of our ethos is a deep love for open source composability, and the HSG v1 does not meet that bar.

Despite the vulnerabilities outlined above in (B), (C), and (D), we still consider HSG v1 sufficiently secure. They imply an assumption that the signers are semi-trusted, which today is generally the case anyways for a typical multisig within an organization.

But we’re not satisfied with this scenario. Part of our mission is to enable organizations to delegate authorities and responsibilities to operators across the full trust spectrum. To do so for multisig signing permissions, therefore, we want to close down these vulnerabilities as best we can without harming legitimate delegated operations.

## Differences between v1 and v2

Here’s what we’re changing in v2 to address the limitations described above.

### 1) Simpler, more legible threshold logic

HSG v2 will set the Safe's threshold to the lower of the following:

- The number of current owners on the Safe (the number of "static signers")
- The required number of valid signatures to execute a transaction

Since (b) is a function of (a), this means that the threshold value set in Safe storage is independent of whether the Safe owners are wearing one of the signer Hats. As a result, unlike in v1, there will never be a discrepancy between what the Safe threshold is and what it should be.

One tradeoff is that the threshold according to the Safe is not necessarily the same as the number of valid signatures that will be enforced by HSG. If, for example, one or more of the Safe owners has lost their Hat, its possible that the actual number of required valid signatures is lower than the threshold set in Safe storage.

### 2) Proportional threshold option

In addition to the absolute approach to calculating the number of required valid signatures that v1 used, v2 introduces an option to calculate the number of valid signatures proportionally.

The absolute approach is a good fit for when the number of signers is expected to be constant over time.

The proportional approach is a good fit for when the number of signers is expected to float up and down according to some external factor.

Both approaches can be configured with a minimum value to ensure the desired level of safety during signer transitions.

### 3) HSG as a Zodiac modifier

This addresses limitation A. Any Safe modules and guards can now be used on a Safe in conjunction HSG. HSG still needs to be the sole module and guard enabled directly on the Safe, but the HSG owner can enable additional modules and guards on HSG. In other words, HSG now serves as a Zodiac modifier.

For a guard enabled on HSG, HSG’s own guard functions will include a call to the guard.

For a module enabled on HSG, HSG exposes its own execTransactionFromModule function that forwards the call to Safe’s execTransactionFromModule. Note that these calls are subject to the same safety checks as those initiated by the signers.

### 4) Only allow delegatecalls to approved targets

This addresses limitations B and C. In HSG v2, the owner can set a list of approved targets for delegatecalls. Delegatecalls to targets not on this list are rejected.

HSG is deployed by default with Safe’s MultiSendCallOnly library for Safe versions v1.3.0 and v1.4.1. This enables batched transactions from Safe apps without any custom configuration.

The owner is trusted to not approve malicious or unsafe contracts. For example, they should not approve the MultiSend library, since that would allow arbitrary delegatecalls.

### 5) Prevent changes to the fallback handler

HSG v2’s suite of safety checks prevents changes to the fallback handler.

### 6) Leverage transient storage for gas savings

In many of its safety checks, HSG stores a copy of Safe storage values to ensure they are not changed by a Safe transaction. In v2, this is done with transient storage for significant gas savings.

Note that this means that HSG v2 cannot be deployed to chains that do have support for TSTORE or TLOAD (EIP 1153).

### 7) Better reentrancy logic

Reentrancy creates a specific type of vulnerability in HSG. To prevent Safe signers and modules from changing any Safe state, HSG temporarily stores a pre-execution copy of the values of key state (owners, threshold, tx operation, and fallback handler). If those values are manipulated by reentering the functions where they are set, the protections would break down.

In v1, there was only one function that set these pre-execution values. In v2, there are two: i) checkTransaction, and ii) execTransactionFromModule and execTransactionFromModuleReturnData.

In (ii), we can use a fairly standard reentrancy guard: revert if either execTransactionFromModule or execTransactionFromModuleReturnData have already been entered. Our design should allow multiple legitimate external calls to one or both functions, but disallow reentrance from within the same call that could override our copy of the Safe state.

Since (i) is called as part of a multi-call flow originating from Safe.execTransaction, we need a slightly different approach. The goal is to ensure the checkTransaction is only called once per time that Safe.execTransaction is called. If checkTransaction is called more, our cached state could be overwritten. To do this, we use the fact that the Safe nonce increments only from within the execTransaction to calculate how many times Safe.execTransaction has been called and compare that to a count of how many times checkTransaction has been entered.

Note that there is a relationship between (i) and (ii). We also need to ensure that (i) is not entered from within a call to (ii), and vice versa.

### 8) Only 1 implementation: all HSGs support multiple signer hats

To simplify the implementation, HSG v2 supports multiple signer hats. This means that all signers must register the hat with which they are claiming their signer permission.

### 9) No max signers value

v1 had a max signers value to ensure that there were no more than the desired number of signers. This was redundant, since the maximum could also be managed via the max supply of the signer hat(s). v2 removes this redundant requirement, simplifying some of the logic and making it easier to get started.

### 10) Detaching and migrating

This addresses limitation G. In v2, the owner can now detach HSG from the Safe, handing over full control over the Safe to its existing signers.

The owner can also choose to migrate the Safe from one HSG version to another. This is useful for upgrading to a future v3 of HSG, or if the owner wants to start clean with a new instance for whatever reason. When migrating, the owner can include a list of signers to migrate.

### 11) Locking

In HSG v2, the owner can “lock” the HSG, disabling any further changes by the owner. This is useful for scenarios where removing all trust from the system or eliminating uncertainty is valuable.

### 12) Claiming For

In HSG v2, the owner can optionally allow signer permissions to be claimed on behalf of accounts wearing a signer hat. This option removes the often-desired requirement for signers to opt in to the responsibility being a signer on a multisig, but adds the ability to integrate signer permissions claiming with external actions.

### 13) No dedicated factory

In contrast to the dedicated factory used by v1, v2 is deployed via the Zodiac Module Factory. This makes it easier to deploy HSG to new chains and will also make it easier to deploy new versions or future flavors of HSG.

To enable paired deployment of HSG with a Safe, the Safe can optionally be deployed and configured from within HSG’s setUp function.
