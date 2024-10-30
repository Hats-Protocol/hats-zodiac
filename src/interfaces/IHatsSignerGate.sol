// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { ISafe } from "../lib/safe-interfaces/ISafe.sol";
import { IHats } from "../../lib/hats-protocol/src/Interfaces/IHats.sol";

/// @notice Interface for the HatsSignerGate contract
interface IHatsSignerGate {
  /*//////////////////////////////////////////////////////////////
                            DATA TYPES
  //////////////////////////////////////////////////////////////*/

  /// @notice The type of target threshold
  /// @param ABSOLUTE An absolute number of signatures
  /// @param PROPORTIONAL A percentage of the total number of signers, in basis points (10000 = 100%)
  enum TargetThresholdType {
    ABSOLUTE, // 0
    PROPORTIONAL // 1

  }

  /// @notice Struct for the threshold configuration
  /// @param thresholdType The type of target threshold, either ABSOLUTE or PROPORTIONAL
  /// @param min The minimum threshold
  /// @param target The target threshold
  struct ThresholdConfig {
    TargetThresholdType thresholdType;
    uint120 min;
    uint120 target;
  }

  /// @notice Struct for the parameters passed to the `setUp` function
  /// @param ownerHat The ID of the owner hat
  /// @param signerHats The IDs of the signer hats
  /// @param safe The address of the safe
  /// @param thresholdConfig The threshold configuration
  /// @param locked Whether the contract is locked
  /// @param claimableFor Whether signer permissions can be claimed on behalf of valid hat wearers
  /// @param implementation The address of the HatsSignerGate implementation
  /// @param hsgGuard The address of the initial guard set on the HatsSignerGate instance
  /// @param hsgModules The initial modules set on the HatsSignerGate instance
  struct SetupParams {
    uint256 ownerHat;
    uint256[] signerHats;
    address safe;
    ThresholdConfig thresholdConfig;
    bool locked;
    bool claimableFor;
    address implementation;
    address hsgGuard;
    address[] hsgModules;
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

  /// @notice Thrown when the number of signatures from valid signers is less than the correct threshold
  error InsufficientValidSignatures();

  /// @notice This contract can only be set once as a zodiac guard on `safe`
  error GuardAlreadySet();

  /// @notice Can't remove a signer if they're still wearing the signer hat
  error StillWearsSignerHat(address signer);

  /// @notice Invalid threshold configuration
  // TODO enumerate all the conditions that cause this error
  error InvalidThresholdConfig();

  /// @notice Signers already on the `safe` cannot claim twice
  error SignerAlreadyRegistered(address signer);

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

  /// @notice Signer permissions cannot be claimed on behalf of valid hat wearers if this is not set
  error NotClaimableFor();

  /// @notice The input arrays must be the same length
  error InvalidArrayLength();

  /// @notice Neither Safe signers nor modules enabled on HSG can make external calls to the `safe`
  /// @dev This ensures that signers and modules cannot change any of the `safe`'s settings
  error CannotCallSafe();

  /// @notice The delegatecall target is not enabled
  error DelegatecallTargetNotEnabled();

  /// @notice Reregistration is not allowed on behalf of an existing signer
  error ReregistrationNotAllowed();

  /*//////////////////////////////////////////////////////////////
                              EVENTS
  //////////////////////////////////////////////////////////////*/

  /// @notice Emitted when the threshold configuration is set
  event ThresholdConfigSet(ThresholdConfig thresholdConfig);

  /// @notice Emitted when new approved signer hats are added
  event SignerHatsAdded(uint256[] newSignerHats);

  /// @notice Emitted when the owner hat is updated
  event OwnerHatUpdated(uint256 ownerHat);

  /// @notice Emitted when the contract is locked, preventing any further changes to settings
  event HSGLocked();

  /// @notice Emitted when the claimableFor parameter is set
  event ClaimableForSet(bool claimableFor);

  /// @notice Emitted when HSG has been detached from its avatar Safe
  event Detached();

  /// @notice Emitted when HSG has been migrated to a new HSG
  event Migrated(address newHSG);

  /// @notice Emitted when a delegatecall target is enabled
  event DelegatecallTargetEnabled(address target, bool enabled);

  /// @notice Emitted when a signer registers the hat that makes them a valid signer
  event Registered(uint256 hatId, address signer);

  /*//////////////////////////////////////////////////////////////
                          CONSTANTS
  //////////////////////////////////////////////////////////////*/

  /// @notice The Hats Protocol contract address
  function HATS() external view returns (IHats);

  /// @notice The version of this HatsSignerGate contract
  function version() external view returns (string memory);

  /*//////////////////////////////////////////////////////////////
                          STATE VARIABLES
  //////////////////////////////////////////////////////////////*/

  /// @notice Append-only tracker of approved signer hats
  function validSignerHats(uint256) external view returns (bool);

  /// @notice Tracks the hat ids worn by users who have "claimed signer"
  function claimedSignerHats(address) external view returns (uint256);

  /// @notice Tracks enabled delegatecall targets. Enabled targets can be delegatecalled by the `safe`
  function enabledDelegatecallTargets(address) external view returns (bool);

  /// @notice The owner hat
  function ownerHat() external view returns (uint256);

  /// @notice The `safe` to which this contract is attached
  function safe() external view returns (ISafe);

  /// @notice The threshold configuration
  function thresholdConfig() external view returns (ThresholdConfig memory);

  /// @notice The address of the HatsSignerGate implementation
  function implementation() external view returns (address);

  /// @notice Whether the contract is locked. If true, the owner cannot change any of the contract's settings.
  function locked() external view returns (bool);

  /// @notice Whether signer permissions can be claimed on behalf of valid hat wearers
  function claimableFor() external view returns (bool);

  /*//////////////////////////////////////////////////////////////
                              FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  // TODO make sure all functions implemented in HatsSignerGate are included here

  /// @notice Initializes a new instance of HatsSignerGate.
  /// @dev Does NOT check if the target Safe is compatible with this HSG.
  /// @dev Can only be called once
  /// @param initializeParams ABI-encoded bytes with initialization parameters, as defined in
  /// {IHatsSignerGate.SetupParams}
  function setUp(bytes calldata initializeParams) external payable;

  /// @notice Claims signer permissions for the caller. Must be a valid wearer of `_hatId`.
  /// @dev If the `_signer` is not already an owner on the `safe`, they are added as a new owner.
  /// @param _hatId The hat id to claim signer rights for
  function claimSigner(uint256 _hatId) external;

  /// @notice Claims signer permissions for a valid wearer of `_hatId` on behalf of `_signer`.
  /// @dev If the `_signer` is not already an owner on the `safe`, they are added as a new owner.
  /// @param _hatId The hat id to claim signer rights for
  /// @param _signer The address to claim signer rights for
  function claimSignerFor(uint256 _hatId, address _signer) external;

  /// @notice Claims signer permissions for a set of valid wearers of `_hatIds` on behalf of the `_signers`
  /// If this contract is the only owner on the `safe`, it will be swapped out for the first `_signer`. Otherwise, each
  /// of the `_signers` will be added as a new owner.
  /// @param _hatIds The hat ids to use for adding each of the `_signers`, indexed to `_signers`
  /// @param _signers The addresses to add as new `safe` owners, indexed to `_hatIds`
  function claimSignersFor(uint256[] calldata _hatIds, address[] calldata _signers) external;

  /// @notice Removes an invalid signer from the `safe`, updating the threshold if appropriate
  /// @param _signer The address to remove if not a valid signer
  function removeSigner(address _signer) external;

  /// @notice Irreversibly locks the contract, preventing any further changes to the contract's settings.
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  function lock() external;

  /// @notice Sets the owner hat
  /// @dev Only callable by a wearer of the current owner hat, and only if the contract is not locked
  /// @param _ownerHat The new owner hat
  function setOwnerHat(uint256 _ownerHat) external;

  /// @notice Adds new approved signer hats
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _newSignerHats Array of hat ids to add as approved signer hats
  function addSignerHats(uint256[] calldata _newSignerHats) external;

  /// @notice Sets a new threshold configuration
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _thresholdConfig The new threshold configuration
  function setThresholdConfig(ThresholdConfig memory _thresholdConfig) external;

  /// @notice Sets whether signer permissions can be claimed on behalf of valid hat wearers
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _claimableFor Whether signer permissions can be claimed on behalf of valid hat wearers
  function setClaimableFor(bool _claimableFor) external;

  /// @notice Detach HSG from the Safe
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  function detachHSG() external;

  /// @notice Migrate the Safe to a new HSG, ie detach this HSG and attach a new HSG
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _newHSG The new HatsSignerGate to attach to the Safe
  /// @param _signerHatIds The hat ids to use for adding each of the `_signersToMigrate`, indexed to `_signersToMigrate`
  /// @param _signersToMigrate The addresses to add as new `safe` owners, indexed to `_signerHatIds`, empty if no
  /// signers to migrate. `_newHSG` must have claimableFor==TRUE to migrate signers.
  function migrateToNewHSG(address _newHSG, uint256[] calldata _signerHatIds, address[] calldata _signersToMigrate)
    external;

  /// @notice Enables a target contract to be delegatecall-able by the `safe`.
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _target The target addressto enable
  function enableDelegatecallTarget(address _target) external;

  /// @notice Disables a target contract from being delegatecall-able by the `safe`.
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _target The target address to disable
  function disableDelegatecallTarget(address _target) external;

  /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
  /// @dev Must be implemented by all flavors of HatsSignerGate
  /// @param _account The address to check
  /// @return valid Whether `_account` is a valid signer
  function isValidSigner(address _account) external view returns (bool valid);

  /// @notice A `_hatId` is valid if it is included in the `validSignerHats` mapping
  /// @param _hatId The hat id to check
  /// @return valid Whether `_hatId` is a valid signer hat
  function isValidSignerHat(uint256 _hatId) external view returns (bool valid);

  /// @notice Tallies the number of existing `safe` owners that wear a signer hat
  /// @return signerCount The number of valid signers on the `safe`
  function validSignerCount() external view returns (uint256 signerCount);

  /// @notice Checks if a HatsSignerGate can be safely attached to a Safe, ie there must be no existing modules
  function canAttachToSafe() external view returns (bool);

  /// @notice Counts the number of hats-valid signatures within a set of `signatures`
  /// @dev modified from
  /// https://github.com/safe-global/safe-contracts/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/Safe.sol#L240
  /// @param dataHash The signed data
  /// @param signatures The set of signatures to check
  /// @param sigCount The number of signatures to check
  /// @return validSigCount The number of hats-valid signatures
  function countValidSignatures(bytes32 dataHash, bytes memory signatures, uint256 sigCount)
    external
    view
    returns (uint256 validSigCount);

  /// @notice Returns the addresses of the Safe contracts used to deploy new Safes
  /// @return _safeSingleton The address of the Safe singleton used to deploy new Safes
  /// @return _safeFallbackLibrary The address of the Safe fallback library used to deploy new Safes
  /// @return _safeMultisendLibrary The address of the Safe multisend library used to deploy new Safes
  /// @return _safeProxyFactory The address of the Safe proxy factory used to deploy new Safes
  function getSafeDeployParamAddresses()
    external
    view
    returns (
      address _safeSingleton,
      address _safeFallbackLibrary,
      address _safeMultisendLibrary,
      address _safeProxyFactory
    );
}
