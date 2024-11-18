// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, WithHSGInstanceTest } from "./TestSuite.t.sol";
import { IHats, IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { IAvatar } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { IModuleManager } from "../src/lib/safe-interfaces/IModuleManager.sol";
import { ModifierUnowned } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";

contract ExecutingFromModuleViaHSG is WithHSGInstanceTest {
  address newModule = tstModule1;
  address recipient = makeAddr("recipient");

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    instance.enableModule(newModule);

    // deal the safe some eth
    deal(address(safe), 1 ether);
  }

  function test_happy_executionSuccess() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;
    uint256 postValue = preValue - transferValue;

    // have the new module submit/exec the tx, expecting a success event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleSuccess(address(instance));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleSuccess(newModule);
    vm.prank(newModule);
    instance.execTransactionFromModule(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
  }

  function test_happy_executionFailure() public {
    // craft a call to a function that doesn't exist on a contract (we'll use Hats.sol)
    bytes memory badCall = abi.encodeWithSignature("badCall()");

    // have the new module submit/exec the tx, expecting a failure event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleFailure(address(instance));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleFailure(newModule);
    vm.prank(newModule);
    instance.execTransactionFromModule(address(hats), 0, badCall, Enum.Operation.Call);
  }

  function test_revert_notModule() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;

    // have a non-module submit/exec the tx, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(ModifierUnowned.NotAuthorized.selector, other));
    vm.prank(other);
    instance.execTransactionFromModule(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
  }

  function test_revert_moduleCannotCallSafe() public {
    uint256 transferValue = 0.3 ether;
    // try to send to the safe, expecting a revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    vm.prank(newModule);
    instance.execTransactionFromModule(address(safe), transferValue, hex"00", Enum.Operation.Call);
  }

  function test_revert_delegatecallTargetNotEnabled() public {
    address target = makeAddr("target");

    // craft a delegatecall to a non-enabled target
    bytes memory data = abi.encodeWithSignature("maliciousCall()");

    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(newModule);
    instance.execTransactionFromModule(target, 0, data, Enum.Operation.DelegateCall);
  }
}

contract ExecutingFromModuleReturnDataViaHSG is WithHSGInstanceTest {
  address newModule = tstModule1;
  address recipient = makeAddr("recipient");

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    instance.enableModule(newModule);

    // deal the safe some eth
    deal(address(safe), 1 ether);
  }

  function test_happy_executionSuccess() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;
    uint256 postValue = preValue - transferValue;

    // have the new module submit/exec the tx, expecting a success event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleSuccess(address(instance));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleSuccess(newModule);
    vm.prank(newModule);
    instance.execTransactionFromModuleReturnData(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
  }

  function test_happy_executionFailure() public {
    // craft a call to a function that doesn't exist on a contract (we'll use Hats.sol)
    bytes memory badCall = abi.encodeWithSignature("badCall()");

    // have the new module submit/exec the tx, expecting a failure event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleFailure(address(instance));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleFailure(newModule);
    vm.prank(newModule);
    instance.execTransactionFromModuleReturnData(address(hats), 0, badCall, Enum.Operation.Call);
  }

  function test_revert_notModule() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;

    // have a non-module submit/exec the tx, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(ModifierUnowned.NotAuthorized.selector, other));
    vm.prank(other);
    instance.execTransactionFromModuleReturnData(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
  }

  function test_revert_moduleCannotCallSafe() public {
    uint256 transferValue = 0.3 ether;
    // try to send to the safe, expecting a revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    vm.prank(newModule);
    instance.execTransactionFromModuleReturnData(address(safe), transferValue, hex"00", Enum.Operation.Call);
  }

  function test_revert_delegatecallTargetNotEnabled() public {
    address target = makeAddr("target");

    // craft a delegatecall to a non-enabled target
    bytes memory data = abi.encodeWithSignature("maliciousCall()");

    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(newModule);
    instance.execTransactionFromModuleReturnData(target, 0, data, Enum.Operation.DelegateCall);
  }
}

contract ConstrainingModules is WithHSGInstanceTest {
  address newModule = tstModule1;
  address recipient = makeAddr("recipient");

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    instance.enableModule(newModule);

    // deal the safe some eth
    deal(address(safe), 1 ether);
  }

  function test_revert_delegateCallTargetNotEnabled() public {
    address target = makeAddr("target");

    // encode a call that we know will be successful
    bytes memory data = abi.encodeWithSelector(IHats.isWearerOfHat.selector, signerAddresses[0], signerHat);

    // wrap it in a multisend call
    bytes memory multisendData = abi.encodePacked(
      Enum.Operation.Call, // 0 for call; 1 for delegatecall
      address(hats), // to
      uint256(0), // value
      uint256(data.length), // data length
      data // data
    );

    // encode the multisend call
    bytes memory multisendCall = abi.encodeWithSelector(MultiSend.multiSend.selector, multisendData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModule(target, 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(target, 0, multisendCall, Enum.Operation.DelegateCall);
  }

  function test_revert_modulesCannotDisableModule() public {
    bytes memory disableModuleData =
      abi.encodeWithSignature("disableModule(address,address)", SENTINELS, address(instance));

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(disableModuleData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotChangeModules.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotChangeModules.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotDisableGuard() public {
    bytes memory disableGuardData = abi.encodeWithSignature("setGuard(address)", address(0x0));

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(disableGuardData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotDisableThisGuard.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotDisableThisGuard.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotIncreaseThreshold() public {
    _addSignersSameHat(3, signerHat);

    uint256 oldThreshold = safe.getThreshold();
    assertEq(oldThreshold, 2);

    // data to increase the threshold data by 1
    bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold + 1);

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(changeThresholdData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotDecreaseThreshold() public {
    _addSignersSameHat(3, signerHat);

    uint256 oldThreshold = safe.getThreshold();
    assertEq(oldThreshold, 2);

    // data to decrease the threshold data by 1
    bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold - 1);

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(changeThresholdData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotAddOwners() public {
    // data for call to add owners
    bytes memory addOwnerData = abi.encodeWithSignature(
      "addOwnerWithThreshold(address,uint256)",
      signerAddresses[9], // newOwner
      safe.getThreshold() // threshold
    );

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(addOwnerData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotRemoveOwners() public {
    _addSignersSameHat(3, signerHat);
    address toRemove = signerAddresses[2];

    // data for call to remove owners
    bytes memory removeOwnerData = abi.encodeWithSignature(
      "removeOwner(address,address,uint256)",
      _findPrevOwner(safe.getOwners(), toRemove), // prevOwner
      toRemove, // owner to remove
      safe.getThreshold() // threshold
    );

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(removeOwnerData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_modulesCannotSwapOwners() public {
    _addSignersSameHat(3, signerHat);
    address toRemove = signerAddresses[2];
    address toAdd = signerAddresses[9];
    // data for call to swap owners
    bytes memory swapOwnerData = abi.encodeWithSignature(
      "swapOwner(address,address,address)",
      _findPrevOwner(safe.getOwners(), toRemove), // prevOwner
      toRemove, // owner to swap
      toAdd // newOwner
    );

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(swapOwnerData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }

  function test_revert_delegatecallTargetNotEnabled() public {
    address target = makeAddr("target");

    // craft a delegatecall to a non-enabled target
    bytes memory data = abi.encodeWithSignature("maliciousCall()");

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModule(target, 0, data, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(target, 0, data, Enum.Operation.DelegateCall);
  }

  function test_revert_modulesCannotCallSafe() public {
    uint256 transferValue = 0.2 ether;

    // give the safe some eth
    vm.deal(address(safe), transferValue);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModule(address(safe), transferValue, hex"00", Enum.Operation.Call);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(address(safe), transferValue, hex"00", Enum.Operation.Call);
  }

  function test_revert_cannotChangeFallbackHandler() public {
    address newFallbackHandler = makeAddr("newFallbackHandler");

    // data for call to change the fallback handler
    bytes memory changeFallbackHandlerData = abi.encodeWithSignature("setFallbackHandler(address)", newFallbackHandler);

    (bytes memory multisendCall,) = _constructSingleActionMultiSendTx(changeFallbackHandlerData);

    // try to exec the tx from the newModule, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeFallbackHandler.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModule(defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall);

    // try to exec the tx from the newModuleReturnData, expect it to revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeFallbackHandler.selector));
    vm.prank(address(newModule));
    instance.execTransactionFromModuleReturnData(
      defaultDelegatecallTargets[0], 0, multisendCall, Enum.Operation.DelegateCall
    );
  }
}
