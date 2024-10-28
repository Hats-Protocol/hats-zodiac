// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { Test, console2 } from "../lib/forge-std/src/Test.sol"; // comment out after testing
import { IHats } from "../lib/hats-protocol/src/Interfaces/IHats.sol";
import { SafeManagerLib } from "./lib/SafeManagerLib.sol";
import { IHatsSignerGate } from "./interfaces/IHatsSignerGate.sol";
import { Initializable } from "../lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import { BaseGuard } from "../lib/zodiac/contracts/guard/BaseGuard.sol";
import { GuardableUnowned } from "./lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "./lib/zodiac-modified/ModifierUnowned.sol";
import { SignatureDecoder } from "../lib/safe-smart-account/contracts/common/SignatureDecoder.sol";
import { ISafe, Enum } from "./lib/safe-interfaces/ISafe.sol";

/// @title HatsSignerGate
/// @author Haberdasher Labs
/// @author @spengrah
/// @notice A Zodiac compatible contract for managing a Safe's owners and signatures via Hats Protocol.
/// @dev This contract is designed to work with the Zodiac Module Factory, from which instances are deployed.
// TODO need to reduce bytecode size by 0 kb
contract HatsSignerGate is
  IHatsSignerGate,
  BaseGuard,
  GuardableUnowned,
  ModifierUnowned,
  SignatureDecoder,
  Initializable
{
  using SafeManagerLib for ISafe;

  /*//////////////////////////////////////////////////////////////
                            CONSTANTS
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  IHats public immutable HATS;

  /// @dev The address of the Safe singleton contract used to deploy new Safes
  address internal immutable SAFE_SINGLETON;

  /// @dev The address of the Safe fallback library used to deploy new Safes
  address internal immutable SAFE_FALLBACK_LIBRARY;

  /// @dev The address of the Safe multisend library used to deploy new Safes
  address internal immutable SAFE_MULTISEND_LIBRARY;

  /// @dev The address of the Safe proxy factory used to deploy new Safes
  address internal immutable SAFE_PROXY_FACTORY;

  /// @inheritdoc IHatsSignerGate
  string public constant version = "2.0.0";

  /*//////////////////////////////////////////////////////////////
                            MUTABLE STATE
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  mapping(uint256 => bool) public validSignerHats;

  /// @inheritdoc IHatsSignerGate
  mapping(address => uint256) public claimedSignerHats;

  /// @inheritdoc IHatsSignerGate
  uint256 public ownerHat;

  /// @inheritdoc IHatsSignerGate
  ISafe public safe;

  /// @dev The threshold configuration
  ThresholdConfig internal _thresholdConfig;

  /// @inheritdoc IHatsSignerGate
  bool public locked;

  /// @inheritdoc IHatsSignerGate
  bool public claimableFor;

  /// @inheritdoc IHatsSignerGate
  address public implementation;

  /// @dev Temporary record of the existing owners on the `safe` when a transaction is submitted
  bytes32 internal _existingOwnersHash;

  /// @dev A simple re-entrency guard
  uint256 internal _guardEntries;

  /*//////////////////////////////////////////////////////////////
                      AUTHENTICATION FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev Internal function to check if the caller is wearing the owner hat
  function _checkOwner() internal view {
    if (!HATS.isWearerOfHat(msg.sender, ownerHat)) revert NotOwnerHatWearer();
  }

  /// @dev Internal function to check if the contract is unlocked
  function _checkUnlocked() internal view {
    if (locked) revert Locked();
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
  ) initializer {
    HATS = IHats(_hats);
    SAFE_PROXY_FACTORY = _safeProxyFactory;
    SAFE_SINGLETON = _safeSingleton;
    SAFE_FALLBACK_LIBRARY = _safeFallbackLibrary;
    SAFE_MULTISEND_LIBRARY = _safeMultisendLibrary;

    // set the implementation's owner hat to a nonexistent hat to prevent state changes to the implementation
    ownerHat = 1;
  }

  /*//////////////////////////////////////////////////////////////
                              INITIALIZER
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  function setUp(bytes calldata initializeParams) public payable initializer {
    SetupParams memory params = abi.decode(initializeParams, (SetupParams));

    // deploy a new safe if there is no provided safe
    if (params.safe == address(0)) {
      params.safe = SafeManagerLib.deploySafeAndAttachHSG(
        SAFE_PROXY_FACTORY, SAFE_SINGLETON, SAFE_FALLBACK_LIBRARY, SAFE_MULTISEND_LIBRARY
      );
    }

    // set the instance's owner hat
    _setOwnerHat(params.ownerHat);

    // lock the instance if configured as such
    if (params.locked) _lock();

    // set the instance's claimableFor flag
    _setClaimableFor(params.claimableFor);

    // set the instance's safe and signer parameters
    safe = ISafe(params.safe);
    _addSignerHats(params.signerHats);
    _setThresholdConfig(params.thresholdConfig);

    // set the instance's metadata
    // TODO can we get this from the clone bytecode?
    implementation = params.implementation;

    // initialize the modules linked list, and set initial modules, if any
    setupModules();
    for (uint256 i; i < params.hsgModules.length; ++i) {
      _enableModule(params.hsgModules[i]);
    }

    // set the initial guard, if any
    if (params.hsgGuard != address(0)) _setGuard(params.hsgGuard);
  }

  /*//////////////////////////////////////////////////////////////
                          PUBLIC FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  function claimSigner(uint256 _hatId) public {
    _addSigner(_hatId, msg.sender);
  }

  /// @inheritdoc IHatsSignerGate
  function claimSignerFor(uint256 _hatId, address _signer) public {
    // check that signer permissions are claimable for
    if (!claimableFor) revert NotClaimableFor();

    _addSigner(_hatId, _signer);
  }

  /// @inheritdoc IHatsSignerGate
  function claimSignersFor(uint256[] calldata _hatIds, address[] calldata _signers) public {
    // check that signer permissions are claimable for
    if (!claimableFor) revert NotClaimableFor();

    // check that the arrays are the same length
    uint256 toClaimCount = _signers.length;
    if (_hatIds.length != toClaimCount) revert InvalidArrayLength();

    ISafe s = safe;
    uint256 threshold = s.getThreshold();
    address[] memory owners = s.getOwners();

    // check if the only owner is this contract, meaning no owners have been added yet
    bool isInitialOwnersState = owners.length == 1 && owners[0] == address(this);

    // count the number of owners after the claim
    uint256 newNumOnwers = owners.length;
    // iterate through the arrays, adding each signer
    for (uint256 i; i < toClaimCount; ++i) {
      uint256 hatId = _hatIds[i];
      address signer = _signers[i];

      // register the signer, reverting if invalid or already registered
      _registerSigner(hatId, signer);

      // if the signer is not an owner, add them
      if (!s.isOwner(signer)) {
        // initiate the addOwnerData, to be conditionally set below
        bytes memory addOwnerData;

        // for the first signer, check if the only owner is this contract and swap it out if so
        if (i == 0 && isInitialOwnersState) {
          addOwnerData = SafeManagerLib.encodeSwapOwnerAction(SafeManagerLib.SENTINELS, address(this), signer);
        } else {
          // otherwise, add the claimer as a new owner
          addOwnerData = SafeManagerLib.encodeAddOwnerWithThresholdAction(signer, threshold);
          newNumOnwers++;
        }

        // execute the call
        if (!s.execSafeTransactionFromHSG(addOwnerData)) revert SafeManagerLib.FailedExecAddSigner();
      }
    }

    // update the static threshold if necessary
    uint256 newThreshold = _updatedStaticThreshold(newNumOnwers);
    if (newThreshold != threshold) {
      safe.execChangeThreshold(newThreshold);
    }
  }

  /// @inheritdoc IHatsSignerGate
  function removeSigner(address _signer) public virtual {
    if (isValidSigner(_signer)) revert StillWearsSignerHat(_signer);

    _removeSigner(_signer);
  }

  /*//////////////////////////////////////////////////////////////
                        OWNER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  function lock() public {
    _checkUnlocked();
    _checkOwner();
    _lock();
  }

  /// @inheritdoc IHatsSignerGate
  function setOwnerHat(uint256 _ownerHat) public {
    _checkUnlocked();
    _checkOwner();
    _setOwnerHat(_ownerHat);
  }

  /// @inheritdoc IHatsSignerGate
  function addSignerHats(uint256[] calldata _newSignerHats) external {
    _checkUnlocked();
    _checkOwner();
    _addSignerHats(_newSignerHats);
  }

  /// @inheritdoc IHatsSignerGate
  function setThresholdConfig(ThresholdConfig calldata _config) public {
    _checkUnlocked();
    _checkOwner();
    _setThresholdConfig(_config);

    // update the safe threshold
    address[] memory owners = safe.getOwners();
    uint256 newThreshold = _getCorrectThreshold(owners.length);
    // console2.log("correct threshold", newThreshold);
    if (newThreshold > owners.length) {
      newThreshold = owners.length;
    }

    if (newThreshold != safe.getThreshold()) {
      safe.execChangeThreshold(newThreshold);
    }
  }

  /// @inheritdoc IHatsSignerGate
  function setClaimableFor(bool _claimableFor) public {
    _checkUnlocked();
    _checkOwner();
    _setClaimableFor(_claimableFor);
  }

  /// @inheritdoc IHatsSignerGate
  function detachHSG() public {
    _checkUnlocked();
    _checkOwner();
    ISafe s = safe; // save SLOAD

    // first remove as guard, then as module
    s.execRemoveHSGAsGuard();
    s.execDisableHSGAsOnlyModule();
    emit Detached();
  }

  /// @inheritdoc IHatsSignerGate
  function migrateToNewHSG(address _newHSG, uint256[] calldata _signerHatIds, address[] calldata _signersToMigrate)
    public
  {
    _checkUnlocked();
    _checkOwner();
    // TODO check if _newHSG is indeed an HSG?

    ISafe s = safe; // save SLOADS
    // remove existing HSG as guard
    s.execRemoveHSGAsGuard();
    // enable new HSG as module and guard
    s.execAttachNewHSG(_newHSG);
    // remove existing HSG as module
    s.execDisableHSGAsModule(_newHSG);

    // if _signersToMigrate is provided, migrate them to the new HSG by calling claimSignersFor()
    uint256 toMigrateCount = _signersToMigrate.length;
    if (toMigrateCount > 0) {
      // check that the arrays are the same length
      if (_signerHatIds.length != toMigrateCount) revert InvalidArrayLength();

      IHatsSignerGate(_newHSG).claimSignersFor(_signerHatIds, _signersToMigrate);
    }
    emit Migrated(_newHSG);
  }

  /*//////////////////////////////////////////////////////////////
                      ZODIAC GUARD FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc BaseGuard
  function checkTransaction(
    address to,
    uint256 value,
    bytes memory data, // TODO compile viaIR to return this to calldata without stack too deep error
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures,
    address // msgSender
  ) external override {
    ISafe s = safe; // save SLOADs

    // ensure that the call is coming from the safe
    if (msg.sender != address(s)) revert NotCalledFromSafe();

    // module guard preflight check
    if (guard != address(0)) {
      BaseGuard(guard).checkTransaction(
        to,
        value,
        data,
        operation,
        // Zero out the redundant transaction information only used for Safe multisig transctions.
        0,
        0,
        0,
        address(0),
        payable(0),
        "",
        address(0)
      );
    }

    // get the tx hash
    bytes32 txHash = s.getTransactionHash(
      to,
      value,
      data,
      operation,
      safeTxGas,
      baseGas,
      gasPrice,
      gasToken,
      refundReceiver,
      // We subtract 1 since nonce was just incremented in the parent function call
      s.nonce() - 1 // view function
    );

    // get the safe owners
    address[] memory owners = s.getOwners();
    uint256 correctThreshold = _getCorrectThreshold(owners.length);
    uint256 threshold = s.getThreshold();

    if (threshold != correctThreshold) revert InsufficientValidSignatures();

    uint256 validSigCount = countValidSignatures(txHash, signatures, threshold);

    // revert if there aren't enough valid signatures
    if (validSigCount < threshold) revert InsufficientValidSignatures();

    // record existing owners for post-flight check
    // TODO use TSTORE
    _existingOwnersHash = keccak256(abi.encode(owners));

    // TODO use TSTORE
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
    ISafe s = safe; // save SLOADs
    if (msg.sender != address(s)) revert NotCalledFromSafe();
    // prevent signers from disabling this guard

    // module guard postflight check
    if (guard != address(0)) {
      BaseGuard(guard).checkAfterExecution(bytes32(0), false);
    }

    if (s.getSafeGuard() != address(this)) revert CannotDisableThisGuard(address(this));

    // get the owners
    address[] memory owners = s.getOwners();

    // prevent signers from changing the threshold
    if (s.getThreshold() != _getCorrectThreshold(owners.length)) revert SignersCannotChangeThreshold();

    // prevent signers from changing the owners
    if (keccak256(abi.encode(owners)) != _existingOwnersHash) revert SignersCannotChangeOwners();

    // prevent signers from removing this module or adding any other modules
    (address[] memory modulesWith1, address next) = s.getModulesWith1();

    // ensure that there is only one module...
    // if the length is 0, we know this module has been removed
    // per Safe ModuleManager.sol#137, "If all entries fit into a single page, the next pointer will be 0x1", ie
    // SENTINELS. Therefore, if `next` is not SENTINELS, we know another module has been added.
    if (modulesWith1.length == 0 || next != SafeManagerLib.SENTINELS) revert SignersCannotChangeModules();
    // ...and that the only module is this contract
    else if (modulesWith1[0] != address(this)) revert SignersCannotChangeModules();

    // leave checked to catch underflows triggered by re-entry attempts
    --_guardEntries;
  }

  /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @inheritdoc IHatsSignerGate
  function thresholdConfig() public view returns (ThresholdConfig memory) {
    return _thresholdConfig;
  }

  /// @inheritdoc IHatsSignerGate
  function isValidSigner(address _account) public view returns (bool valid) {
    /// @dev existing `claimedSignerHats` are always valid, since `validSignerHats` is append-only
    valid = HATS.isWearerOfHat(_account, claimedSignerHats[_account]);
  }

  /// @inheritdoc IHatsSignerGate
  function isValidSignerHat(uint256 _hatId) public view returns (bool valid) {
    valid = validSignerHats[_hatId];
  }

  /// @inheritdoc IHatsSignerGate
  function validSignerCount() public view returns (uint256 signerCount) {
    signerCount = _countValidSigners(safe.getOwners());
  }

  /// @inheritdoc IHatsSignerGate
  function canAttachToSafe() public view returns (bool) {
    return safe.canAttachHSG();
  }

  /// @inheritdoc IHatsSignerGate
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

    for (i; i < sigCount; ++i) {
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
    }
  }

  /// @inheritdoc IHatsSignerGate
  function getSafeDeployParamAddresses()
    public
    view
    returns (
      address _safeSingleton,
      address _safeFallbackLibrary,
      address _safeMultisendLibrary,
      address _safeProxyFactory
    )
  {
    return (SAFE_SINGLETON, SAFE_FALLBACK_LIBRARY, SAFE_MULTISEND_LIBRARY, SAFE_PROXY_FACTORY);
  }

  /*//////////////////////////////////////////////////////////////
                      INTERNAL HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev Internal function to set the owner hat
  /// @param _ownerHat The hat id to set as the owner hat
  function _setOwnerHat(uint256 _ownerHat) internal {
    ownerHat = _ownerHat;
    emit OwnerHatUpdated(_ownerHat);
  }

  // /// @notice Checks if `_account` is a valid signer
  // /// @dev Must be implemented by all flavors of HatsSignerGate
  // /// @param _account The address to check
  // /// @return valid Whether `_account` is a valid signer
  // function isValidSigner(address _account) public view virtual returns (bool valid) { }

  /// @dev Internal function to approve new signer hats
  /// @param _newSignerHats Array of hat ids to add as approved signer hats
  function _addSignerHats(uint256[] memory _newSignerHats) internal {
    for (uint256 i; i < _newSignerHats.length; ++i) {
      validSignerHats[_newSignerHats[i]] = true;
    }

    emit SignerHatsAdded(_newSignerHats);
  }

  function _setThresholdConfig(ThresholdConfig memory _config) internal {
    if (_config.thresholdType == TargetThresholdType.ABSOLUTE) {
      // absolute targetthreshold cannot be lower than min threshold
      if (_config.target < _config.min) revert InvalidThresholdConfig();
    } else if (_config.thresholdType == TargetThresholdType.PROPORTIONAL) {
      // proportional threshold cannot be greater than 100%
      if (_config.target > 10_000) revert InvalidThresholdConfig();
    } else {
      // invalid threshold type
      revert InvalidThresholdConfig();
    }

    // set the threshold config
    _thresholdConfig = _config;

    // log the change
    emit ThresholdConfigSet(_config);
  }

  /// @dev Internal function to count the number of valid signers in an array of addresses
  /// @param owners The addresses to check for validity
  /// @return signerCount The number of valid signers in `owners`
  function _countValidSigners(address[] memory owners) internal view returns (uint256 signerCount) {
    uint256 length = owners.length;
    // count the existing safe owners that wear the signer hat
    for (uint256 i; i < length; ++i) {
      if (isValidSigner(owners[i])) {
        // shouldn't overflow given reasonable owners array length
        unchecked {
          ++signerCount;
        }
      }
    }
  }

  /// @dev Internal function to set the claimableFor parameter
  /// @param _claimableFor Whether signer permissions are claimable on behalf of valid hat wearers
  function _setClaimableFor(bool _claimableFor) internal {
    claimableFor = _claimableFor;
    emit ClaimableForSet(_claimableFor);
  }

  /// @dev Internal function to register a signer's hat. Includes checks for signer/hat validity and prior registration.
  /// @param _hatId The hat id to register
  /// @param _signer The address to register
  function _registerSigner(uint256 _hatId, address _signer) internal {
    // check that the hat is valid
    if (!isValidSignerHat(_hatId)) revert InvalidSignerHat(_hatId);

    // check that the signer is wearing the hat
    if (!HATS.isWearerOfHat(_signer, _hatId)) revert NotSignerHatWearer(_signer);

    // don't try to add an owner that has already registered
    if (claimedSignerHats[_signer] == _hatId) revert SignerAlreadyClaimed(_signer);

    // register the hat used to claim. This will be the hat checked in `checkTransaction()` for this signer
    claimedSignerHats[_signer] = _hatId;
  }

  /// @dev Internal function to add a `_signer` to the `safe` if they are wearing a valid signer hat.
  /// If this contract is the only owner on the `safe`, it will be swapped out for `_signer`. Otherwise, `_signer` will
  /// be added as a new owner. If the `_signer` is already an owner but has not registered their hat, they will be
  /// registered but not re-added to the `safe`.
  /// @param _hatId The hat id to use for the claim
  /// @param _signer The address to add as a new `safe` owner
  function _addSigner(uint256 _hatId, address _signer) internal {
    // register the signer
    _registerSigner(_hatId, _signer);

    ISafe s = safe;

    // if the signer is not already an owner, add them
    if (!s.isOwner(_signer)) {
      // get the current owners
      address[] memory owners = s.getOwners();

      // initiate the addOwnerData, to be conditionally set below
      bytes memory addOwnerData;

      // if the only owner is this contract (set as an owner on initialization), replace it with _signer
      if (owners.length == 1 && owners[0] == address(this)) {
        // set up the swapOwner call
        addOwnerData = SafeManagerLib.encodeSwapOwnerAction(SafeManagerLib.SENTINELS, address(this), _signer);
      } else {
        // update the threshold
        uint256 newThreshold = _updatedStaticThreshold(owners.length + 1);
        // set up the addOwner call
        addOwnerData = SafeManagerLib.encodeAddOwnerWithThresholdAction(_signer, newThreshold);
      }

      // execute the call
      if (!s.execSafeTransactionFromHSG(addOwnerData)) revert SafeManagerLib.FailedExecAddSigner();
    }
  }

  /// @dev Internal function to remove a signer from the `safe`, updating the threshold if appropriate
  /// Unsafe. Does not check for signer validity before removal
  /// @param _signer The address to remove
  function _removeSigner(address _signer) internal {
    bytes memory removeOwnerData;
    address[] memory owners = safe.getOwners();

    delete claimedSignerHats[_signer];

    if (owners.length == 1) {
      // make address(this) the only owner
      removeOwnerData = SafeManagerLib.encodeSwapOwnerAction(SafeManagerLib.SENTINELS, _signer, address(this));
    } else {
      // update the threshold
      uint256 newThreshold = _updatedStaticThreshold(owners.length - 1);

      removeOwnerData =
        SafeManagerLib.encodeRemoveOwnerAction(SafeManagerLib.findPrevOwner(owners, _signer), _signer, newThreshold);
    }

    // execute the call
    if (!safe.execSafeTransactionFromHSG(removeOwnerData)) revert SafeManagerLib.FailedExecRemoveSigner();
  }

  /// @dev Internal function to calculate the threshold that `safe` should have, given the correct `signerCount` and
  /// threshold config
  /// @return _threshold The correct threshold
  function _getCorrectThreshold(uint256 numOwners) internal view returns (uint256 _threshold) {
    // get the threshold config
    ThresholdConfig memory config = _thresholdConfig;

    // calculate the correct threshold
    if (config.thresholdType == TargetThresholdType.ABSOLUTE) {
      // ABSOLUTE
      if (numOwners < config.min) _threshold = config.min;
      else if (numOwners > config.target) _threshold = config.target;
      else _threshold = numOwners;
    } else {
      // PROPORTIONAL
      // add 9999 to round up
      _threshold = ((numOwners * config.target) + 9999) / 10_000;
      // ensure that the threshold is not lower than 1
      if (_threshold < config.min) _threshold = config.min;
    }
  }

  function _updatedStaticThreshold(uint256 numOwners) internal view returns (uint256 _threshold) {
    _threshold = _getCorrectThreshold(numOwners);
    // the static threshold cannot be higher than the number of owners
    if (_threshold > numOwners) {
      _threshold = numOwners;
    }
  }

  /// @dev Locks the contract, preventing any further owner changes
  function _lock() internal {
    locked = true;
    emit HSGLocked();
  }

  // solhint-disallow-next-line payable-fallback
  fallback() external {
    // We don't revert on fallback to avoid issues in case of a Safe upgrade
    // E.g. The expected check method might change and then the Safe would be locked.
  }

  // /*//////////////////////////////////////////////////////////////
  //                     ZODIAC MODIFIER FUNCTIONS
  // //////////////////////////////////////////////////////////////*/

  /// @dev Allows a Module to execute a transaction.
  /// @notice Can only be called by an enabled module.
  /// @notice Must emit ExecutionFromModuleSuccess(address module) if successful.
  /// @notice Must emit ExecutionFromModuleFailure(address module) if unsuccessful.
  /// @param to Destination address of module transaction.
  /// @param value Ether value of module transaction.
  /// @param data Data payload of module transaction.
  /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
  function execTransactionFromModule(address to, uint256 value, bytes calldata data, Enum.Operation operation)
    public
    override
    moduleOnly
    returns (bool success)
  {
    // disallow external calls to the safe
    if (to == address(safe)) revert ModulesCannotCallSafe();

    // forward the call to the safe
    success = safe.execTransactionFromModule(to, value, data, operation);

    // emit the appropriate execution status event
    if (success) {
      emit ExecutionFromModuleSuccess(msg.sender);
    } else {
      emit ExecutionFromModuleFailure(msg.sender);
    }
  }

  /// @dev Allows a Module to execute a transaction and return data
  /// @notice Can only be called by an enabled module.
  /// @notice Must emit ExecutionFromModuleSuccess(address module) if successful.
  /// @notice Must emit ExecutionFromModuleFailure(address module) if unsuccessful.
  /// @param to Destination address of module transaction.
  /// @param value Ether value of module transaction.
  /// @param data Data payload of module transaction.
  /// @param operation Operation type of module transaction: 0 == call, 1 == delegate call.
  function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, Enum.Operation operation)
    public
    override
    moduleOnly
    returns (bool success, bytes memory returnData)
  {
    // disallow external calls to the safe
    if (to == address(safe)) revert ModulesCannotCallSafe();

    // forward the call to the safe
    (success, returnData) = safe.execTransactionFromModuleReturnData(to, value, data, operation);

    // emit the appropriate execution status event
    if (success) {
      emit ExecutionFromModuleSuccess(msg.sender);
    } else {
      emit ExecutionFromModuleFailure(msg.sender);
    }
  }

  /// @inheritdoc ModifierUnowned
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  function disableModule(address prevModule, address module) public override {
    _checkUnlocked();
    _checkOwner();
    super.disableModule(prevModule, module);
  }

  /// @notice Enables a module that can add transactions to the queue
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param module Address of the module to be enabled
  function enableModule(address module) public {
    _checkUnlocked();
    _checkOwner();
    _enableModule(module);
  }

  /*//////////////////////////////////////////////////////////////
                      ZODIAC GUARD FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @notice Set a guard that checks transactions before execution.
  /// @dev Only callable by a wearer of the owner hat, and only if the contract is not locked.
  /// @param _guard The address of the guard to be used or the 0 address to disable the guard.
  function setGuard(address _guard) public {
    _checkUnlocked();
    _checkOwner();
    _setGuard(_guard);
  }
}
