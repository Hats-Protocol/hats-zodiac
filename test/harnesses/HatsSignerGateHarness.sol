// SPDX-License-Identifier: LGPL-3.0
pragma solidity >=0.8.13;

// import { Test, console2 } from "../lib/forge-std/src/Test.sol"; // comment out after testing
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
}
