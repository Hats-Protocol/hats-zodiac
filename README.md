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
2. Removing the contract as a module on the multisig — or removing/changing/adding any other modules
3. Changing the multisig threshold
4. Changing the multisig owners
5. Making delegatecalls to any target not approved by the owner

> **Warning**
> Protections against (3) and (4) above only hold if the Safe does not have any authority over the signer Hat(s). If it does — e.g. it wears an admin Hat of the signer Hat(s) or is an eligibility or toggle module on the signer Hat(s) — then in some cases the signers may be able to change the multisig threshold or owners.
>
> Proceed with caution if granting such authority to a Safe attached to HatsSignerGate.

### Signer Management

Hats Signer Gate provides several ways to manage Safe signers based on their hat-wearing status:

#### Claiming Signer Rights

- Individual hat wearers can claim their own signing rights via `claimSigner()`
- Must be wearing a valid signer hat at time of claim
- Each signer's hat ID is registered and tracked for future validation

#### Claiming for Others

When enabled by the owner (`claimableFor = true`):

- Anyone can claim signing rights on behalf of valid hat wearers via `claimSignerFor()` or `claimSignersFor()`
- Useful for batch onboarding of signers
- Prevents re-registration if signer is still wearing their currently registered hat

#### Signer Removal

- Signers who no longer wear their registered hat can be removed via `removeSigner()`
- Threshold automatically adjusts according to the threshold configuration
- If the removed signer was the last valid signer, the contract itself becomes the sole owner

### Threshold Configuration

The threshold (number of required signatures) is managed dynamically based on the `ThresholdConfig`:

#### Threshold Types

1. **ABSOLUTE**

   - Sets a fixed target number of required signatures
   - Example: Always require exactly 3 signatures
   - Bounded by min threshold and number of valid signers

2. **PROPORTIONAL**

   - Sets a percentage of total signers required (in basis points)
   - Example: Require 51% of signers (5100 basis points)
   - Actual number of required signatures rounds up
   - Still bounded by min threshold

#### Configuration Parameters

- `min`: Minimum number of required signatures (must be > 0)
- `target`: Either fixed number (ABSOLUTE) or percentage in basis points (PROPORTIONAL)
- `thresholdType`: ABSOLUTE (0) or PROPORTIONAL (1)

The Safe's threshold is automatically adjusted when:

- New signers are added
- Existing signers are removed
- Threshold configuration is changed

### Delegatecall Targets

HSG restricts delegatecalls to protect the Safe from unauthorized modifications. Only approved targets can receive delegatecalls.

#### Default Enabled Targets

The following MultiSend libraries are enabled by default:

| Address | Version | Type |
| --- | --- | --- |
| `0x40A2aCCbd92BCA938b02010E17A5b8929b49130D` | v1.3.0 | canonical |
| `0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B` | v1.3.0 | eip155 |
| `0x9641d764fc13c8B624c04430C7356C1C7C8102e2` | v1.4.1 | canonical |

See [safe-deployments](https://github.com/safe-global/safe-deployments/tree/main/src/assets) for more information.

#### Security Considerations

- Delegatecalls can modify Safe state if not properly restricted
- HSG validates that approved delegatecalls don't modify critical Safe parameters
- Direct calls to the Safe are always prohibited

### Contract Ownership

The wearer of the `ownerHat` can make the following changes to Hats Signer Gate:

1. "Transfer" ownership to a new Hat by changing the `ownerHat`
2. Change the threshold configuration
3. Enable other Zodiac modules on HSG itself
4. Enable another Zodiac guard on HSG itself
5. Add other Hats as valid signer Hats
6. Enable or disable the ability for others to claim signer rights on behalf of valid hat wearers (`claimableFor`)
7. Detach HatsSignerGate from the Safe (removing it as both guard and module)
8. Migrate to a new HatsSignerGate instance
9. Enable or disable specific delegatecall targets
10. Lock the contract permanently, preventing any further owner changes

### Deploying New Instances

Instances of HSG can be created via the [Zodiac module proxy factory](https://github.com/gnosisguild/zodiac/blob/18b7575bb342424537883f7ebe0a94cd7f3ec4f6/contracts/factory/ModuleProxyFactory.sol).

Instances can be created for an existing Safe by passing the Safe address on initialization, or for a new Safe to be deployed from within HSG's initialization.

### Security Audits

v1 of this project has received the following security audits. See the [audits directory](./audits/) for the detailed reports.

| Auditor | Report Date | Commit Hash | Notes |
| --- | --- | --- | --- |
| Trust Security | Feb 23, 2023 | [b9b7fcf](https://github.com/Hats-Protocol/hats-zodiac/commit/b9b7fcf22fd5cbb98c7d93dead590e80bf9c780a) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |
| Sherlock | May 3, 2023 | [9455c0](https://github.com/Hats-Protocol/hats-zodiac/commit/9455cc0957762f5dbbd8e62063d970199109b977) | Report also includes findings from [Hats Protocol](https://github.com/Hats-Protocol/hats-protocol) audit |

v2 — the present version — of this project will be audited soon.

### Recent Deployments

See [Releases](https://github.com/Hats-Protocol/hats-zodiac/releases) for deployments. Specific deployment parameters are [stored here](./script/DeployParams.json).
