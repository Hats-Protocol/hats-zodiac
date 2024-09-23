// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { Test, console2 } from "forge-std/Test.sol"; // comment out after testing
import { IHats } from "../lib/hats-protocol/src/Interfaces/IHats.sol";
import { SafeDeployer } from "./SafeDeployer.sol";
import { IHatsSignerGate, HSGEvents } from "./interfaces/IHatsSignerGate.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { BaseGuard } from "lib/zodiac/contracts/guard/BaseGuard.sol";
import { StorageAccessible } from "lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { SignatureDecoder } from "lib/safe-smart-account/contracts/common/SignatureDecoder.sol";
import { ISafe, Enum } from "./lib/safe-interfaces/ISafe.sol";

contract HatsSignerGate is IHatsSignerGate, SafeDeployer, BaseGuard, SignatureDecoder, Initializable {
  /*//////////////////////////////////////////////////////////////
                           CONSTANTS
  //////////////////////////////////////////////////////////////*/

  IHats public immutable HATS;

  /// @dev The head pointer used in the Safe owners linked list, as well as the module linked list
  address internal constant SENTINELS = address(0x1);

  /// @dev The storage slot used by Safe to store the guard address
  ///      keccak256("guard_manager.guard.address")
  bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

  /*//////////////////////////////////////////////////////////////
                            MUTABLE STATE
  //////////////////////////////////////////////////////////////*/

  /// @notice Append-only tracker of approved signer hats
  mapping(uint256 => bool) public validSignerHats;

  /// @notice Tracks the hat ids worn by users who have "claimed signer"
  mapping(address => uint256) public claimedSignerHats;

  /// @notice The id of the owner hat
  uint256 public ownerHat;

  /// @notice The multisig to which this contract is attached
  ISafe public safe;

  /// @notice The minimum signature threshold for the `safe`
  uint256 public minThreshold;

  /// @notice The highest level signature threshold for the `safe`
  uint256 public targetThreshold;

  /// @notice The maximum number of signers allowed for the `safe`
  uint256 public maxSigners;

  /// @notice The version of HatsSignerGate used in this contract
  string public version;

  /// @dev Temporary record of the existing owners on the `safe` when a transaction is submitted
  bytes32 internal _existingOwnersHash;

  /// @dev A simple re-entrency guard
  uint256 internal _guardEntries;

  /*//////////////////////////////////////////////////////////////
                              MODIFIERS
  //////////////////////////////////////////////////////////////*/

  modifier onlyOwner() {
    if (!HATS.isWearerOfHat(msg.sender, ownerHat)) {
      revert NotOwnerHatWearer();
    }
    _;
  }

  /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
  //////////////////////////////////////////////////////////////*/

  constructor(
    address _hats,
    address _safeSingleton,
    address _safeFallbackLibrary,
    address _safeMultisendLibrary,
    address _safeProxyFactory
  ) SafeDeployer(_safeSingleton, _safeFallbackLibrary, _safeMultisendLibrary, _safeProxyFactory) initializer {
    HATS = IHats(_hats);

    // set the implementation's owner hat to a nonexistent hat to prevent state changes to the implementation
    ownerHat = 1;
  }

  /*//////////////////////////////////////////////////////////////
                              INITIALIZER
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Initializes a new instance of MultiHatsSignerGate
   * @dev Can only be called once
   * @param initializeParams ABI-encoded bytes with initialization parameters
   * @custom:field _ownerHatId The id of the owner hat
   * @custom:field _signerHats The ids of the signer hats
   * @custom:field _safe The address of the existing safe, or zero address to deploy a new safe
   * @custom:field _minThreshold The minimum signature threshold
   * @custom:field _targetThreshold The target signature threshold
   * @custom:field _maxSigners The maximum number of signers
   * @custom:field _version The version of the contract
   */
  function setUp(bytes calldata initializeParams) public payable initializer {
    (
      uint256 _ownerHatId,
      uint256[] memory _signerHats,
      address _safe,
      uint256 _minThreshold,
      uint256 _targetThreshold,
      uint256 _maxSigners,
      string memory _version
    ) = abi.decode(initializeParams, (uint256, uint256[], address, uint256, uint256, uint256, string));

    bool emptySafe = _safe == address(0);

    if (emptySafe) {
      _safe = _deploySafeAndAttachHSG();
    }

    _setUpHSG(_ownerHatId, _safe, _minThreshold, _targetThreshold, _maxSigners, _version);

    _addSignerHats(_signerHats);

    // TODO optimize this so that we don't have to do another if statement here
    if (!emptySafe) {
      if (!_canAttachToSafe(ISafe(_safe))) revert CannotAttachToSafe();
    }
  }

  /*//////////////////////////////////////////////////////////////
                          PUBLIC FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Function to become an owner on the safe if you are wearing `_hatId` and `_hatId` is a valid signer hat
  /// @dev Reverts if `maxSigners` has been reached, the caller is either invalid or has already claimed. Swaps caller
  /// with existing invalid owner if relevant.
  /// @param _hatId The hat id to claim signer rights for
  function claimSigner(uint256 _hatId) public {
    uint256 maxSigs = maxSigners; // save SLOADs
    address[] memory owners = safe.getOwners();

    uint256 currentSignerCount = _countValidSigners(owners);

    if (currentSignerCount >= maxSigs) {
      revert MaxSignersReached();
    }

    if (safe.isOwner(msg.sender)) {
      revert SignerAlreadyClaimed(msg.sender);
    }

    if (!isValidSignerHat(_hatId)) {
      revert InvalidSignerHat(_hatId);
    }

    if (!HATS.isWearerOfHat(msg.sender, _hatId)) {
      revert NotSignerHatWearer(msg.sender);
    }

    /* 
        We check the safe owner count in case there are existing owners who are no longer valid signers. 
        If we're already at maxSigners, we'll replace one of the invalid owners by swapping the signer.
        Otherwise, we'll simply add the new signer.
        */
    uint256 ownerCount = owners.length;

    if (ownerCount >= maxSigs) {
      bool swapped = _swapSigner(owners, ownerCount, msg.sender);
      if (!swapped) {
        // if there are no invalid owners, we can't add a new signer, so we revert
        revert NoInvalidSignersToReplace();
      }
    } else {
      _grantSigner(owners, currentSignerCount, msg.sender);
    }

    // register the hat used to claim. This will be the hat checked in `checkTransaction()` for this signer
    claimedSignerHats[msg.sender] = _hatId;
  }

  /// @notice Removes an invalid signer from the `safe`, updating the threshold if appropriate
  /// @param _signer The address to remove if not a valid signer
  function removeSigner(address _signer) public virtual {
    if (isValidSigner(_signer)) {
      revert StillWearsSignerHat(_signer);
    }

    _removeSigner(_signer);
  }

  /// @notice Tallies the number of existing `safe` owners that wear a signer hat and updates the `safe` threshold if
  /// necessary
  /// @dev Does NOT remove invalid `safe` owners
  function reconcileSignerCount() public {
    uint256 signerCount = validSignerCount();

    if (signerCount > maxSigners) {
      revert MaxSignersReached();
    }

    uint256 currentThreshold = safe.getThreshold();
    uint256 newThreshold;
    uint256 target = targetThreshold; // save SLOADs

    if (signerCount <= target && signerCount != currentThreshold) {
      newThreshold = signerCount;
    } else if (signerCount > target && currentThreshold < target) {
      newThreshold = target;
    }
    if (newThreshold > 0) {
      bytes memory data = abi.encodeWithSignature("changeThreshold(uint256)", newThreshold);

      bool success = safe.execTransactionFromModule(
        address(safe), // to
        0, // value
        data, // data
        Enum.Operation.Call // operation
      );

      if (!success) {
        revert FailedExecChangeThreshold();
      }
    }
  }

  /*//////////////////////////////////////////////////////////////
                        OWNER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Sets the owner hat
  /// @dev Only callable by a wearer of the current owner hat
  /// @param _ownerHat The new owner hat
  function setOwnerHat(uint256 _ownerHat) public onlyOwner {
    ownerHat = _ownerHat;
    emit HSGEvents.OwnerHatUpdated(_ownerHat);
  }

  /// @notice Sets a new target threshold, and changes `safe`'s threshold if appropriate
  /// @dev Only callable by a wearer of the owner hat. Reverts if `_targetThreshold` is greater than `maxSigners`.
  /// @param _targetThreshold The new target threshold to set
  function setTargetThreshold(uint256 _targetThreshold) public onlyOwner {
    if (_targetThreshold != targetThreshold) {
      _setTargetThreshold(_targetThreshold);

      uint256 signerCount = validSignerCount();
      if (signerCount > 1) _setSafeThreshold(_targetThreshold, signerCount);

      emit HSGEvents.TargetThresholdSet(_targetThreshold);
    }
  }

  /// @notice Sets a new minimum threshold
  /// @dev Only callable by a wearer of the owner hat. Reverts if `_minThreshold` is greater than `maxSigners` or
  /// `targetThreshold`
  /// @param _minThreshold The new minimum threshold
  function setMinThreshold(uint256 _minThreshold) public onlyOwner {
    _setMinThreshold(_minThreshold);
    emit HSGEvents.MinThresholdSet(_minThreshold);
  }

  /*//////////////////////////////////////////////////////////////
                      ZODIAC GUARD FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Pre-flight check on a `safe` transaction to ensure that it s signers are valid, called from within
  /// `safe.execTransactionFromModule()`
  /// @dev Overrides All params mirror params for `safe.execTransactionFromModule()`
  function checkTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures,
    address // msgSender
  ) external override {
    if (msg.sender != address(safe)) revert NotCalledFromSafe();
    // get the safe owners
    address[] memory owners = safe.getOwners();
    {
      // scope to avoid stack too deep errors
      uint256 safeOwnerCount = owners.length;
      // uint256 validSignerCount = _countValidSigners(safe.getOwners());
      // ensure that safe threshold is correct
      reconcileSignerCount();

      if (safeOwnerCount < minThreshold) {
        revert BelowMinThreshold(minThreshold, safeOwnerCount);
      }
    }
    // get the tx hash; view function
    bytes32 txHash = safe.getTransactionHash(
      // Transaction info
      to,
      value,
      data,
      operation,
      safeTxGas,
      // Payment info
      baseGas,
      gasPrice,
      gasToken,
      refundReceiver,
      // Signature info
      // We subtract 1 since nonce was just incremented in the parent function call
      safe.nonce() - 1 // view function
    );
    uint256 threshold = safe.getThreshold();
    uint256 validSigCount = countValidSignatures(txHash, signatures, threshold);

    // revert if there aren't enough valid signatures
    if (validSigCount < threshold || validSigCount < minThreshold) {
      revert InvalidSigners();
    }

    // record existing owners for post-flight check
    _existingOwnersHash = keccak256(abi.encode(owners));

    unchecked {
      ++_guardEntries;
    }
    // revert if re-entry is detected
    if (_guardEntries > 1) revert NoReentryAllowed();
  }

  /**
   * @notice Post-flight check to prevent `safe` signers from performing any of the following actions:
   *         1. removing this contract guard
   *         2. changing any modules
   *         3. changing the threshold
   *         4. changing the owners
   *     CAUTION: If the safe has any authority over the signersHat(s) — i.e. wears their admin hat(s) or is an
   *     eligibility or toggle module — then in some cases protections (3) and (4) may not hold. Proceed with caution if
   *     considering granting such authority to the safe.
   * @dev Modified from
   * https://github.com/gnosis/zodiac-guard-mod/blob/988ebc7b71e352f121a0be5f6ae37e79e47a4541/contracts/ModGuard.sol#L86
   */
  function checkAfterExecution(bytes32, bool) external override {
    if (msg.sender != address(safe)) revert NotCalledFromSafe();
    // prevent signers from disabling this guard
    if (
      abi.decode(StorageAccessible(address(safe)).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address))
        != address(this)
    ) {
      revert CannotDisableThisGuard(address(this));
    }
    // prevent signers from changing the threshold
    if (safe.getThreshold() != _getCorrectThreshold()) {
      revert SignersCannotChangeThreshold();
    }
    // prevent signers from changing the owners
    address[] memory owners = safe.getOwners();
    if (keccak256(abi.encode(owners)) != _existingOwnersHash) {
      revert SignersCannotChangeOwners();
    }
    // prevent signers from removing this module or adding any other modules
    /// @dev SENTINELS and SENTINEL_MODULES are both address(0x1)
    (address[] memory modulesWith1, address next) = safe.getModulesPaginated(SENTINELS, 1);
    // ensure that there is only one module...
    if (
      // if the length is 0, we know this module has been removed
      // per Safe ModuleManager.sol#137, "If all entries fit into a single page, the next pointer will be 0x1", ie
      // SENTINELS. Therefore, if `next` is not SENTINELS, we know another module has been added.
      modulesWith1.length == 0 || next != SENTINELS
    ) {
      revert SignersCannotChangeModules();
    } // ...and that the only module is this contract
    else if (modulesWith1[0] != address(this)) {
      revert SignersCannotChangeModules();
    }
    // leave checked to catch underflows triggered by re-entry attempts
    --_guardEntries;
  }

  /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
  /// @dev Must be implemented by all flavors of HatsSignerGate
  /// @param _account The address to check
  /// @return valid Whether `_account` is a valid signer
  function isValidSigner(address _account) public view returns (bool valid) {
    /// @dev existing `claimedSignerHats` are always valid, since `validSignerHats` is append-only
    valid = HATS.isWearerOfHat(_account, claimedSignerHats[_account]);
  }

  /// @notice Adds new approved signer hats
  /// @param _newSignerHats Array of hat ids to add as approved signer hats
  function addSignerHats(uint256[] calldata _newSignerHats) external onlyOwner {
    _addSignerHats(_newSignerHats);

    emit HSGEvents.SignerHatsAdded(_newSignerHats);
  }

  /// @notice A `_hatId` is valid if it is included in the `validSignerHats` mapping
  /// @param _hatId The hat id to check
  /// @return valid Whether `_hatId` is a valid signer hat
  function isValidSignerHat(uint256 _hatId) public view returns (bool valid) {
    valid = validSignerHats[_hatId];
  }

  /// @notice Tallies the number of existing `safe` owners that wear a signer hat
  /// @return signerCount The number of valid signers on the `safe`
  function validSignerCount() public view returns (uint256 signerCount) {
    signerCount = _countValidSigners(safe.getOwners());
  }

  /**
   * @notice Checks if a HatsSignerGate can be safely attached to a Safe
   * @dev There must be...
   *      1) No existing modules on the Safe
   *      2) HatsSignerGate's `validSignerCount()` must be <= `_maxSigners`
   */
  function canAttachToSafe() public view returns (bool) {
    return _canAttachToSafe(safe);
  }

  /// @notice Counts the number of hats-valid signatures within a set of `signatures`
  /// @dev modified from
  /// https://github.com/safe-global/safe-contracts/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/Safe.sol#L240
  /// @param dataHash The signed data
  /// @param signatures The set of signatures to check
  /// @return validSigCount The number of hats-valid signatures
  function countValidSignatures(bytes32 dataHash, bytes memory signatures, uint256 sigCount)
    public
    view
    returns (uint256 validSigCount)
  {
    // There cannot be an owner with address 0.
    address currentOwner;
    uint8 v;
    bytes32 r;
    bytes32 s;
    uint256 i;

    for (i; i < sigCount;) {
      (v, r, s) = signatureSplit(signatures, i);
      if (v == 0) {
        // If v is 0 then it is a contract signature
        // When handling contract signatures the address of the contract is encoded into r
        currentOwner = address(uint160(uint256(r)));
      } else if (v == 1) {
        // If v is 1 then it is an approved hash
        // When handling approved hashes the address of the approver is encoded into r
        currentOwner = address(uint160(uint256(r)));
      } else if (v > 30) {
        // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
        // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before
        // applying ecrecover
        currentOwner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
      } else {
        // Default is the ecrecover flow with the provided data hash
        // Use ecrecover with the messageHash for EOA signatures
        currentOwner = ecrecover(dataHash, v, r, s);
      }

      if (isValidSigner(currentOwner)) {
        // shouldn't overflow given reasonable sigCount
        unchecked {
          ++validSigCount;
        }
      }
      // shouldn't overflow given reasonable sigCount
      unchecked {
        ++i;
      }
    }
  }

  /*//////////////////////////////////////////////////////////////
                      INTERNAL HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Internal function to initialize a new instance
  /// @param _ownerHatId The hat id of the hat that owns this instance of HatsSignerGate
  /// @param _safe The multisig to which this instance of HatsSignerGate is attached
  /// @param _minThreshold The minimum threshold for the `_safe`
  /// @param _targetThreshold The maxium threshold for the `_safe`
  /// @param _maxSigners The maximum number of signers allowed on the `_safe`
  /// @param _version The current version of HatsSignerGate
  function _setUpHSG(
    uint256 _ownerHatId,
    address _safe,
    uint256 _minThreshold,
    uint256 _targetThreshold,
    uint256 _maxSigners,
    string memory _version
  ) internal {
    ownerHat = _ownerHatId;

    maxSigners = _maxSigners;
    safe = ISafe(_safe);

    _setTargetThreshold(_targetThreshold);
    _setMinThreshold(_minThreshold);
    version = _version;

    emit HSGEvents.OwnerHatUpdated(_ownerHatId);
  }

  /**
   * @notice Checks if a HatsSignerGate can be safely attached to a Safe
   * @dev There must be...
   *      1) No existing modules on the Safe
   *      2) HatsSignerGate's `validSignerCount()` must be <= `_maxSigners`
   */
  function _canAttachToSafe(ISafe _safe) internal view returns (bool) {
    (address[] memory modulesWith1,) = _safe.getModulesPaginated(SENTINELS, 1);

    return (modulesWith1.length == 0);

    // QUESTION: do we need to bring back the valid signer count <= maxSigners check?
    // return (modulesWith1.length == 0 && _countValidSigners(_safe.getOwners()) <= maxSigners);
  }

  // /// @notice Checks if `_account` is a valid signer
  // /// @dev Must be implemented by all flavors of HatsSignerGate
  // /// @param _account The address to check
  // /// @return valid Whether `_account` is a valid signer
  // function isValidSigner(address _account) public view virtual returns (bool valid) { }

  /// @notice Internal function to approve new signer hats
  /// @param _newSignerHats Array of hat ids to add as approved signer hats
  function _addSignerHats(uint256[] memory _newSignerHats) internal {
    for (uint256 i = 0; i < _newSignerHats.length;) {
      validSignerHats[_newSignerHats[i]] = true;

      // should not overflow with feasible array length
      unchecked {
        ++i;
      }
    }
  }

  /// @notice Internal function to set the target threshold
  /// @dev Reverts if `_targetThreshold` is greater than `maxSigners` or lower than `minThreshold`
  /// @param _targetThreshold The new target threshold to set
  function _setTargetThreshold(uint256 _targetThreshold) internal {
    // target threshold cannot be lower than min threshold
    if (_targetThreshold < minThreshold) {
      revert InvalidTargetThreshold();
    }
    // target threshold cannot be greater than max signers
    if (_targetThreshold > maxSigners) {
      revert InvalidTargetThreshold();
    }

    targetThreshold = _targetThreshold;
  }

  /// @notice Internal function to set the threshold for the `safe`
  /// @dev Forwards the threshold-setting call to `safe.ExecTransactionFromModule`
  /// @param _threshold The threshold to set on the `safe`
  /// @param _signerCount The number of valid signers on the `safe`; should be calculated from `validSignerCount()`
  function _setSafeThreshold(uint256 _threshold, uint256 _signerCount) internal {
    uint256 newThreshold = _threshold;

    // ensure that txs can't execute if fewer signers than target threshold
    if (_signerCount <= _threshold) {
      newThreshold = _signerCount;
    }
    if (newThreshold != safe.getThreshold()) {
      bytes memory data = abi.encodeWithSignature("changeThreshold(uint256)", newThreshold);

      bool success = safe.execTransactionFromModule(
        address(safe), // to
        0, // value
        data, // data
        Enum.Operation.Call // operation
      );

      if (!success) {
        revert FailedExecChangeThreshold();
      }
    }
  }

  /// @notice Internal function to set a new minimum threshold
  /// @dev Only callable by a wearer of the owner hat. Reverts if `_minThreshold` is greater than `maxSigners` or
  /// `targetThreshold`
  /// @param _minThreshold The new minimum threshold
  function _setMinThreshold(uint256 _minThreshold) internal {
    if (_minThreshold > maxSigners || _minThreshold > targetThreshold) {
      revert InvalidMinThreshold();
    }

    minThreshold = _minThreshold;
  }

  /// @notice Internal function to count the number of valid signers in an array of addresses
  /// @param owners The addresses to check for validity
  /// @return signerCount The number of valid signers in `owners`
  function _countValidSigners(address[] memory owners) internal view returns (uint256 signerCount) {
    uint256 length = owners.length;
    // count the existing safe owners that wear the signer hat
    for (uint256 i; i < length;) {
      if (isValidSigner(owners[i])) {
        // shouldn't overflow given reasonable owners array length
        unchecked {
          ++signerCount;
        }
      }
      // shouldn't overflow given reasonable owners array length
      unchecked {
        ++i;
      }
    }
  }

  /// @notice Internal function that adds `_signer` as an owner on `safe`, updating the threshold if appropriate
  /// @dev Unsafe. Does not check if `_signer` is a valid signer
  /// @param _owners Array of owners on the `safe`
  /// @param _currentSignerCount The current number of signers
  /// @param _signer The address to add as a new `safe` owner
  function _grantSigner(address[] memory _owners, uint256 _currentSignerCount, address _signer) internal {
    uint256 newSignerCount = _currentSignerCount;

    uint256 currentThreshold = safe.getThreshold(); // view function
    uint256 newThreshold = currentThreshold;

    bytes memory addOwnerData;

    // if the only owner is a non-signer (ie this module set as an owner on initialization), replace it with _signer
    if (_owners.length == 1 && _owners[0] == address(this)) {
      // prevOwner will always be the sentinel when owners.length == 1

      // set up the swapOwner call
      addOwnerData = abi.encodeWithSignature(
        "swapOwner(address,address,address)",
        SENTINELS, // prevOwner
        address(this), // oldOwner
        _signer // newOwner
      );
      unchecked {
        // shouldn't overflow given MaxSignersReached check higher in call stack
        ++newSignerCount;
      }
    } else {
      // otherwise, add the claimer as a new owner

      unchecked {
        // shouldn't overflow given MaxSignersReached check higher in call stack
        ++newSignerCount;
      }

      // ensure that txs can't execute if fewer signers than target threshold
      if (newSignerCount <= targetThreshold) {
        newThreshold = newSignerCount;
      }

      // set up the addOwner call
      addOwnerData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", _signer, newThreshold);
    }

    // execute the call
    bool success = safe.execTransactionFromModule(
      address(safe), // to
      0, // value
      addOwnerData, // data
      Enum.Operation.Call // operation
    );

    if (!success) {
      revert FailedExecAddSigner();
    }
  }

  /// @notice Internal function that adds `_signer` as an owner on `safe` by swapping with an existing (invalid) owner
  /// @dev Unsafe. Does not check if `_signer` is a valid signer.
  /// @param _owners Array of owners on the `safe`
  /// @param _ownerCount The number of owners on the `safe` (length of `_owners` array)
  /// @param _signer The address to add as a new `safe` owner
  /// @return success Whether an invalid signer was found and successfully replaced with `_signer`
  function _swapSigner(address[] memory _owners, uint256 _ownerCount, address _signer) internal returns (bool success) {
    address ownerToCheck;
    bytes memory data;

    for (uint256 i; i < _ownerCount;) {
      ownerToCheck = _owners[i];

      if (!isValidSigner(ownerToCheck)) {
        // prep the swap
        data = abi.encodeWithSignature(
          "swapOwner(address,address,address)",
          _findPrevOwner(_owners, ownerToCheck), // prevOwner
          ownerToCheck, // oldOwner
          _signer // newOwner
        );

        // execute the swap, reverting if it fails for some reason
        success = safe.execTransactionFromModule(
          address(safe), // to
          0, // value
          data, // data
          Enum.Operation.Call // operation
        );

        if (!success) {
          revert FailedExecRemoveSigner();
        }

        break;
      }
      unchecked {
        ++i;
      }
    }
  }

  /// @notice Internal function to remove a signer from the `safe`, updating the threshold if appropriate
  /// @dev Unsafe. Does not check for signer validity before removal
  /// @param _signer The address to remove
  function _removeSigner(address _signer) internal {
    bytes memory removeOwnerData;
    address[] memory owners = safe.getOwners();
    uint256 validSigners = _countValidSigners(owners);
    // uint256 newSignerCount;

    if (validSigners < 2 && owners.length == 1) {
      // signerCount could be 0 after reconcileSignerCount
      // make address(this) the only owner
      removeOwnerData = abi.encodeWithSignature(
        "swapOwner(address,address,address)",
        SENTINELS, // prevOwner
        _signer, // oldOwner
        address(this) // newOwner
      );

      // newSignerCount is already 0
    } else {
      uint256 currentThreshold = safe.getThreshold();
      uint256 newThreshold = currentThreshold;
      // uint256 validSignerCount = _countValidSigners(owners);

      // ensure that txs can't execute if fewer signers than target threshold
      if (validSigners <= targetThreshold) {
        newThreshold = validSigners;
      }

      removeOwnerData = abi.encodeWithSignature(
        "removeOwner(address,address,uint256)", _findPrevOwner(owners, _signer), _signer, newThreshold
      );
    }

    bool success = safe.execTransactionFromModule(
      address(safe), // to
      0, // value
      removeOwnerData, // data
      Enum.Operation.Call // operation
    );

    if (!success) {
      revert FailedExecRemoveSigner();
    }
  }

  /// @notice Internal function to find the previous owner of an `_owner` in an array of `_owners`, ie the pointer to
  /// the owner to remove from the `safe` owners linked list
  /// @param _owners An array of addresses
  /// @param _owner The address after the one to find
  /// @return prevOwner The owner previous to `_owner` in the `safe` linked list
  function _findPrevOwner(address[] memory _owners, address _owner) internal pure returns (address prevOwner) {
    prevOwner = SENTINELS;

    for (uint256 i; i < _owners.length;) {
      if (_owners[i] == _owner) {
        if (i == 0) break;
        prevOwner = _owners[i - 1];
      }
      // shouldn't overflow given reasonable _owners array length
      unchecked {
        ++i;
      }
    }
  }

  // solhint-disallow-next-line payable-fallback
  fallback() external {
    // We don't revert on fallback to avoid issues in case of a Safe upgrade
    // E.g. The expected check method might change and then the Safe would be locked.
  }

  /// @notice Internal function to calculate the threshold that `safe` should have, given the correct `signerCount`,
  /// `minThreshold`, and `targetThreshold`
  /// @return _threshold The correct threshold
  function _getCorrectThreshold() internal view returns (uint256 _threshold) {
    uint256 count = validSignerCount();
    uint256 min = minThreshold;
    uint256 max = targetThreshold;
    if (count < min) _threshold = min;
    else if (count > max) _threshold = max;
    else _threshold = count;
  }
}
