// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { Enum, ISafe } from "../lib/safe-interfaces/ISafe.sol";

/// @notice Events emitted by the HatsSignerGate contract
library HSGEvents {
  /// @notice Emitted when a new target signature threshold for the `safe` is set
  event TargetThresholdSet(uint256 threshold);

  /// @notice Emitted when a new minimum signature threshold for the `safe` is set
  event MinThresholdSet(uint256 threshold);

  /// @notice Emitted when new approved signer hats are added
  event SignerHatsAdded(uint256[] newSignerHats);

  /// @notice Emitted when the owner hat is updated
  event OwnerHatUpdated(uint256 ownerHat);

  /// @notice Emitted when the maximum number of signers is set
  event MaxSignersSet(uint256 maxSigners);

  /// @notice Emitted when the contract is locked, preventing any further changes to settings
  event Locked();

  /// @notice Emitted when HSG has been detached from its avatar Safe
  event Detached();

  /// @notice Emitted when HSG has been migrated to a new HSG
  event Migrated(address newHSG);
}

/// @notice Interface for the HatsSignerGate contract
interface IHatsSignerGate {
  /*//////////////////////////////////////////////////////////////
                            STRUCTS
  //////////////////////////////////////////////////////////////*/

  /// @notice Struct for the parameters passed to the `setUp` function
  /// @param ownerHat The ID of the owner hat
  /// @param signerHats The IDs of the signer hats
  /// @param safe The address of the safe
  /// @param minThreshold The minimum signature threshold
  /// @param targetThreshold The target signature threshold
  /// @param maxSigners The maximum number of signers
  /// @param locked Whether the contract is locked
  /// @param implementation The address of the HatsSignerGate implementation
  struct SetupParams {
    uint256 ownerHat;
    uint256[] signerHats;
    address safe;
    uint256 minThreshold;
    uint256 targetThreshold;
    uint256 maxSigners;
    bool locked;
    address implementation;
  }

  /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
  //////////////////////////////////////////////////////////////*/

  /// @notice Signers are not allowed to disable the HatsSignerGate guard
  error CannotDisableThisGuard(address guard);

  /// @notice Only the wearer of the owner Hat can make changes to this contract
  error NotOwnerHatWearer();

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

  /// @notice Emitted when a valid signer attempts `claimSigner` but there are already `maxSigners` signers
  /// @dev This will only occur if `signerCount` is out of sync with the current number of valid signers, which can be
  /// resolved by calling `reconcileSignerCount`
  error NoInvalidSignersToReplace();

  /// @notice Target threshold must be lower than `maxSigners`
  error InvalidTargetThreshold();

  /// @notice Min threshold cannot be higher than `maxSigners` or `targetThreshold`
  error InvalidMinThreshold();

  /// @notice Max signers cannot be less than `targetThreshold` or `validSignerCount`
  error InvalidMaxSigners();

  /// @notice Signers already on the `safe` cannot claim twice
  error SignerAlreadyClaimed(address signer);

  /// @notice Cannot exececute a tx if `safeOnwerCount` < `minThreshold`
  error BelowMinThreshold(uint256 minThreshold, uint256 safeOwnerCount);

  /// @notice Can only claim signer with a valid signer hat
  error InvalidSignerHat(uint256 hatId);

  /// @notice Signers are not allowed to change the threshold
  error SignersCannotChangeThreshold();

  /// @notice Signers are not allowed to add new modules
  error SignersCannotChangeModules();

  /// @notice Signers are not allowed to change owners
  error SignersCannotChangeOwners();

  /// @notice Emmitted when a call to `checkTransaction` or `checkAfterExecution` is not made from the `safe`
  /// @dev Together with `guardEntries`, protects against arbitrary reentrancy attacks by the signers
  error NotCalledFromSafe();

  /// @notice Emmitted when attempting to reenter `checkTransaction`
  /// @dev The Safe will catch this error and re-throw with its own error message (`GS013`)
  error NoReentryAllowed();

  /// @notice Owner cannot change settings once the contract is locked
  error Locked();

  /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  // TODO make sure all functions implemented in HatsSignerGate are included here

  function setUp(bytes calldata initializeParams) external payable;
  function claimSigner(uint256 _hatId) external;
  function removeSigner(address _signer) external;
  function reconcileSignerCount() external;
  function lock() external;
  function setOwnerHat(uint256 _ownerHat) external;
  function setTargetThreshold(uint256 _targetThreshold) external;
  function setMinThreshold(uint256 _minThreshold) external;
  function addSignerHats(uint256[] calldata _newSignerHats) external;
  function detachHSG() external;
  function migrateToNewHSG(address _newHSG) external;

  // function checkTransaction(
  //   address to,
  //   uint256 value,
  //   bytes calldata data,
  //   Enum.Operation operation,
  //   uint256 safeTxGas,
  //   uint256 baseGas,
  //   uint256 gasPrice,
  //   address gasToken,
  //   address payable refundReceiver,
  //   bytes memory signatures,
  //   address msgSender
  // ) external;

  // function checkAfterExecution(bytes32 txHash, bool success) external;

  function isValidSigner(address _account) external view returns (bool valid);
  function isValidSignerHat(uint256 _hatId) external view returns (bool valid);
  function validSignerCount() external view returns (uint256 signerCount);
  function canAttachToSafe() external view returns (bool);
  function countValidSignatures(bytes32 dataHash, bytes memory signatures, uint256 sigCount)
    external
    view
    returns (uint256 validSigCount);

  /*//////////////////////////////////////////////////////////////
                          STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
  function validSignerHats(uint256) external view returns (bool);
  function claimedSignerHats(address) external view returns (uint256);
  function safe() external view returns (ISafe);
  function minThreshold() external view returns (uint256);
  function targetThreshold() external view returns (uint256);
  function maxSigners() external view returns (uint256);
  function version() external view returns (string memory);
}
