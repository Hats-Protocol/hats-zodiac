// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

library HSGLib {
    /// @notice Emitted when a new target signature threshold for the `safe` is set
    event TargetThresholdSet(uint256 threshold);

    /// @notice Emitted when a new minimum signature threshold for the `safe` is set
    event MinThresholdSet(uint256 threshold);

    /// @notice Emitted when new approved signer hats are added
    event SignerHatsAdded(uint256[] newSignerHats);
}

/// @notice Signers are not allowed to disable the HatsSignerGate guard
error CannotDisableThisGuard(address guard);

/// @notice Signers are not allowed to disable the HatsSignerGate module
error CannotDisableProtectedModules(address module);

/// @notice Only the wearer of the owner Hat can make changes to this contract
error NotOwnerHatWearer(address user);

/// @notice Only wearers of a valid signer hat can become signers
error NotSignerHatWearer(address user);

/// @notice Valid signers must wear the signer hat at time of execution
error InvalidSigners();

/// @notice This contract can only be set once as a zodiac guard on `safe`
error GuardAlreadySet();

/// @notice Can't remove a signer if they're still wearing the signer hat
error StillWearsSignerHat(address signer);

/// @notice Can never have more signers than designated by `maxSigners`
error MaxSignersReached();

/// @notice Target threshold must be lower than `maxSigners`
error InvalidTargetThreshold();

/// @notice Min threshold cannot be higher than `maxSigners` or `targetThreshold`
error InvalidMinThreshold();

/// @notice Signers already on the `safe` cannot claim twice
error SignerAlreadyClaimed(address signer);

/// @notice Emitted when a call to change the threshold fails
error FailedExecChangeThreshold();

/// @notice Emitted when a call to add a signer fails
error FailedExecAddSigner();

/// @notice Emitted when a call to remove a signer fails
error FailedExecRemoveSigner();

/// @notice Cannot exececute a tx if `safeOnwerCount` < `minThreshold`
error BelowMinThreshold(uint256 minThreshold, uint256 safeOwnerCount);

/// @notice Can only claim signer with a valid signer hat
error InvalidSignerHat(uint256 hatId);

/// @notice Signers are not allowed to change the threshold
error SignersCannotChangeThreshold();

/// @notice Emmitted when a call to `checkTransaction` or `checkAfterExecution` is not made from the `safe`
/// @dev Together with `guardEntries`, protects against arbitrary reentrancy attacks by the signers
error NotCalledFromSafe();
