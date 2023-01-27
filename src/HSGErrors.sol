// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

// Cannot disable this guard
error CannotDisableThisGuard(address guard);

// Cannot disable protected modules
error CannotDisableProtectedModules(address module);

// Must wear the owner hat to make changes to this contract
error NotOwnerHatWearer(address user);

// Must wear the signer hat to become a signer
error NotSignerHatWearer(address user);

// Valid signers must wear the signer hat at time of execution
error InvalidSigners();

// This contract can only be set once as a zodiac guard on `safe`
error GuardAlreadySet();

// Can't remove a signer if they're still wearing the signer hat
error StillWearsSignerHat(address signer);

// This module will always be a signer on the Safe
error NeedAtLeastTwoSigners();

error MaxSignersReached();

// Target threshold must be lower than maxSigners
error InvalidTargetThreshold();

// Min threshold cannot be higher than maxSigners or targetThreshold
error InvalidMinThreshold();

// Signers already owners on the safe don't need to claim
error SignerAlreadyClaimed(address signer);

error FailedExecChangeThreshold();
error FailedExecAddSigner();
error FailedExecRemoveSigner();

// Cannot exec tx if safeOnwerCount < minThreshold
error BelowMinThreshold(uint256 minThreshold, uint256 safeOwnerCount);

// Can only claim signer with a valid signer hat
error InvalidSignerHat(uint256 hatId);
