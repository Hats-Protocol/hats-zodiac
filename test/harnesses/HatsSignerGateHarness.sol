// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { Test, console2 } from "../../lib/forge-std/src/Test.sol"; // comment out after testing
import { IHats } from "../../lib/hats-protocol/src/Interfaces/IHats.sol";
import { HatsSignerGate } from "../../src/HatsSignerGate.sol";
import { SafeManagerLibHarness } from "./SafeManagerLibHarness.sol";
import { IHatsSignerGate } from "../../src/interfaces/IHatsSignerGate.sol";
import { BaseGuard, IGuard } from "../../lib/zodiac/contracts/guard/BaseGuard.sol";
import { GuardableUnowned } from "../../src/lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "../../src/lib/zodiac-modified/ModifierUnowned.sol";
import { Multicallable } from "../../lib/solady/src/utils/Multicallable.sol";
import { SignatureDecoder } from "../../lib/safe-smart-account/contracts/common/SignatureDecoder.sol";
import { ISafe, Enum } from "../../src/lib/safe-interfaces/ISafe.sol";

/// @dev A harness for testing HatsSignerGate internal functions
contract HatsSignerGateHarness is HatsSignerGate, SafeManagerLibHarness {
  constructor(
    address _hats,
    address _safeSingleton,
    address _safeFallbackLibrary,
    address _safeMultisendLibrary,
    address _safeProxyFactory
  ) HatsSignerGate(_hats, _safeSingleton, _safeFallbackLibrary, _safeMultisendLibrary, _safeProxyFactory) { }

  /*//////////////////////////////////////////////////////////////
                        EXPOSED TRANSIENT STATE
  //////////////////////////////////////////////////////////////*/

  bytes32 public existingOwnersHash;
  uint256 public existingThreshold;
  address public existingFallbackHandler;
  Enum.Operation public operation;
  uint256 public guardEntries;

  /*//////////////////////////////////////////////////////////////
                        TRANSIENT STATE SETTERS
  //////////////////////////////////////////////////////////////*/

  function setExistingOwnersHash(bytes32 existingOwnersHash_) public {
    _existingOwnersHash = existingOwnersHash_;
  }

  function setExistingThreshold(uint256 existingThreshold_) public {
    _existingThreshold = existingThreshold_;
  }

  function setExistingFallbackHandler(address existingFallbackHandler_) public {
    _existingFallbackHandler = existingFallbackHandler_;
  }

  /*//////////////////////////////////////////////////////////////
                        EXPOSED INTERNAL FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  function exposed_checkOwner() public view {
    _checkOwner();
  }

  function exposed_checkUnlocked() public view {
    _checkUnlocked();
  }

  function exposed_lock() public {
    _lock();
  }

  function exposed_setDelegatecallTarget(address _target, bool _enabled) public {
    _setDelegatecallTarget(_target, _enabled);
  }

  function exposed_setClaimableFor(bool _claimableFor) public {
    _setClaimableFor(_claimableFor);
  }

  function exposed_registerSigner(uint256 _hatId, address _signer, bool _allowReregistration) public {
    _registerSigner(_hatId, _signer, _allowReregistration);
  }

  function exposed_addSigner(address _signer) public {
    _addSigner(_signer);
  }

  function exposed_removeSigner(address _signer) public {
    _removeSigner(_signer);
  }

  function exposed_setOwnerHat(uint256 _ownerHat) public {
    _setOwnerHat(_ownerHat);
  }

  function exposed_addSignerHats(uint256[] memory _newSignerHats) public {
    _addSignerHats(_newSignerHats);
  }

  function exposed_setThresholdConfig(ThresholdConfig memory _config) public {
    _setThresholdConfig(_config);
  }

  function exposed_countValidSigners(address[] memory owners) public view returns (uint256) {
    return _countValidSigners(owners);
  }

  function exposed_countValidSignatures(bytes32 dataHash, bytes memory signatures, uint256 sigCount)
    public
    view
    returns (uint256)
  {
    return _countValidSignatures(dataHash, signatures, sigCount);
  }

  function exposed_checkModuleTransaction(address _to, Enum.Operation operation_, ISafe _safe) public {
    _checkModuleTransaction(_to, operation_, _safe);
  }

  function exposed_checkSafeState(ISafe _safe) public view {
    _checkSafeState(_safe);
  }

  function exposed_enableModule(address module) public {
    _enableModule(module);
  }

  function exposed_setGuard(address _guard) public {
    _setGuard(_guard);
  }

  function exposed_getRequiredValidSignatures(uint256 numOwners) public view returns (uint256) {
    return _getRequiredValidSignatures(numOwners);
  }

  function exposed_getNewThreshold(uint256 numOwners) public view returns (uint256) {
    return _getNewThreshold(numOwners);
  }

  function exposed_existingOwnersHash() public view returns (bytes32) {
    return _existingOwnersHash;
  }

  function exposed_existingThreshold() public view returns (uint256) {
    return _existingThreshold;
  }

  function exposed_existingFallbackHandler() public view returns (address) {
    return _existingFallbackHandler;
  }

  function exposed_operation() public view returns (Enum.Operation) {
    return _operation;
  }

  function exposed_guardEntries() public view returns (uint256) {
    return _guardEntries;
  }

  /// @dev Exposes the transient state variables set within checkTransaction
  function exposed_checkTransaction(
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation op,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures,
    address sender
  ) public {
    checkTransaction(to, value, data, op, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, sender);

    // store the transient state in persistent storage for access in tests
    guardEntries = _guardEntries;
    operation = _operation;
    existingOwnersHash = _existingOwnersHash;
    existingThreshold = _existingThreshold;
    existingFallbackHandler = _existingFallbackHandler;
  }

  /// @dev Allows tests to call checkAfterExecution by mocking the guardEntries transient state variable
  function exposed_checkAfterExecution(bytes32 _txHash, bool _success) public {
    // force the guardEntries to be 1 as if it were set by checkTransaction
    _guardEntries = 1;

    checkAfterExecution(_txHash, _success);
  }
}
