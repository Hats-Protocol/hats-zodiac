// SPDX-License-Identifier: LGPL-3.0
pragma solidity >=0.8.13;

// import { console2 } from "../lib/forge-std/src/console2.sol";
import { SafeManagerLib } from "../../src/lib/SafeManagerLib.sol";
import { MultiSend } from "../../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeProxyFactory } from "../../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { StorageAccessible } from "../../lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { Enum, ISafe, IGuardManager, IModuleManager, IOwnerManager } from "../../src/lib/safe-interfaces/ISafe.sol";
import { IGuard } from "../../lib/zodiac/contracts/interfaces/IGuard.sol";

/// @dev A harness for testing SafeManagerLib internal functions
contract SafeManagerLibHarness {
  function deploySafeAndAttachHSG(
    address _safeProxyFactory,
    address _safeSingleton,
    address _safeFallbackLibrary,
    address _safeMultisendLibrary
  ) public returns (address payable) {
    return SafeManagerLib.deploySafeAndAttachHSG(
      _safeProxyFactory, _safeSingleton, _safeFallbackLibrary, _safeMultisendLibrary
    );
  }

  function encodeEnableModuleAction(address _moduleToEnable) public pure returns (bytes memory) {
    return SafeManagerLib.encodeEnableModuleAction(_moduleToEnable);
  }

  function encodeDisableModuleAction(address _previousModule, address _moduleToDisable)
    public
    pure
    returns (bytes memory)
  {
    return SafeManagerLib.encodeDisableModuleAction(_previousModule, _moduleToDisable);
  }

  function encodeSetGuardAction(address _guard) public pure returns (bytes memory) {
    return SafeManagerLib.encodeSetGuardAction(_guard);
  }

  function encodeRemoveHSGAsGuardAction() public pure returns (bytes memory) {
    return SafeManagerLib.encodeRemoveHSGAsGuardAction();
  }

  function encodeSwapOwnerAction(address _prevOwner, address _oldOwner, address _newOwner)
    public
    pure
    returns (bytes memory)
  {
    return SafeManagerLib.encodeSwapOwnerAction(_prevOwner, _oldOwner, _newOwner);
  }

  function encodeRemoveOwnerAction(address _prevOwner, address _oldOwner, uint256 _newThreshold)
    public
    pure
    returns (bytes memory)
  {
    return SafeManagerLib.encodeRemoveOwnerAction(_prevOwner, _oldOwner, _newThreshold);
  }

  function encodeAddOwnerWithThresholdAction(address _owner, uint256 _newThreshold) public pure returns (bytes memory) {
    return SafeManagerLib.encodeAddOwnerWithThresholdAction(_owner, _newThreshold);
  }

  function encodeChangeThresholdAction(uint256 _newThreshold) public pure returns (bytes memory) {
    return SafeManagerLib.encodeChangeThresholdAction(_newThreshold);
  }

  function execSafeTransactionFromHSG(ISafe _safe, bytes memory _data) public {
    SafeManagerLib.execSafeTransactionFromHSG(_safe, _data);
  }

  function execDisableHSGAsOnlyModule(ISafe _safe) public {
    SafeManagerLib.execDisableHSGAsOnlyModule(_safe);
  }

  function execDisableHSGAsModule(ISafe _safe, address _previousModule) public {
    SafeManagerLib.execDisableHSGAsModule(_safe, _previousModule);
  }

  function execRemoveHSGAsGuard(ISafe _safe) public {
    SafeManagerLib.execRemoveHSGAsGuard(_safe);
  }

  function execAttachNewHSG(ISafe _safe, address _newHSG) public {
    SafeManagerLib.execAttachNewHSG(_safe, _newHSG);
  }

  function execChangeThreshold(ISafe _safe, uint256 _newThreshold) public {
    SafeManagerLib.execChangeThreshold(_safe, _newThreshold);
  }

  function getSafeGuard(ISafe _safe) public view returns (address) {
    return SafeManagerLib.getSafeGuard(_safe);
  }

  function getSafeFallbackHandler(ISafe _safe) public view returns (address) {
    return SafeManagerLib.getSafeFallbackHandler(_safe);
  }

  function getModulesWith1(ISafe _safe) public view returns (address[] memory modulesWith1, address next) {
    return SafeManagerLib.getModulesWith1(_safe);
  }

  function canAttachHSG(ISafe _safe) public view returns (bool) {
    return SafeManagerLib.canAttachHSG(_safe);
  }

  function findPrevOwner(address[] memory _owners, address _owner) public pure returns (address) {
    return SafeManagerLib.findPrevOwner(_owners, _owner);
  }
}
