// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, ISafe, TestSuite, WithHSGInstanceTest, HatsSignerGate } from "./TestSuite.t.sol";
import { IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { DeployInstance } from "../script/HatsSignerGate.s.sol";
import { IAvatar } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { IModuleManager } from "../src/lib/safe-interfaces/IModuleManager.sol";
import { GuardableUnowned } from "../src/lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { TestGuard } from "./mocks/TestGuard.sol";

contract Deployment is TestSuite {
  // errors from dependencies
  error InvalidInitialization();

  function test_onlyHSG(bool _locked, bool _claimableFor) public {
    // deploy safe with this contract as the single owner
    address[] memory owners = new address[](1);
    owners[0] = address(this);
    ISafe testSafe = _deploySafe(owners, 1, TEST_SALT_NONCE);

    hatsSignerGate = _deployHSG({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _safe: address(testSafe),
      _expectedError: bytes4(0), // no expected error
      _locked: _locked,
      _claimableFor: _claimableFor,
      _hsgGuard: address(tstGuard),
      _hsgModules: tstModules,
      _verbose: false
    });

    assertEq(hatsSignerGate.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(hatsSignerGate.thresholdConfig(), thresholdConfig);
    assertEq(address(hatsSignerGate.HATS()), address(hats));
    assertEq(address(hatsSignerGate.safe()), address(testSafe));
    assertEq(address(hatsSignerGate.implementation()), address(singletonHatsSignerGate));
    assertEq(hatsSignerGate.locked(), _locked);
    assertEq(hatsSignerGate.claimableFor(), _claimableFor);
    assertEq(address(hatsSignerGate.getGuard()), address(tstGuard));
    assertCorrectModules(tstModules);
  }

  function test_andSafe(bool _locked, bool _claimableFor) public {
    (hatsSignerGate, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _locked: _locked,
      _claimableFor: _claimableFor,
      _hsgGuard: address(tstGuard),
      _hsgModules: tstModules,
      _verbose: false
    });

    assertEq(hatsSignerGate.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(hatsSignerGate.thresholdConfig(), thresholdConfig);
    assertEq(address(hatsSignerGate.HATS()), address(hats));
    assertEq(address(hatsSignerGate.safe()), address(safe));
    assertEq(address(hatsSignerGate.implementation()), address(singletonHatsSignerGate));
    assertEq(_getSafeGuard(address(safe)), address(hatsSignerGate));
    assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));
    assertEq(safe.getOwners()[0], address(hatsSignerGate));
    assertEq(hatsSignerGate.locked(), _locked);
    assertEq(hatsSignerGate.claimableFor(), _claimableFor);
    assertEq(address(hatsSignerGate.getGuard()), address(tstGuard));
    assertCorrectModules(tstModules);
  }

  function test_revert_reinitializeImplementation() public {
    bytes memory initializeParams =
      abi.encode(ownerHat, signerHats, address(safe), thresholdConfig, false, address(singletonHatsSignerGate));
    vm.expectRevert(InvalidInitialization.selector);
    singletonHatsSignerGate.setUp(initializeParams);
  }
}

contract AddingSignerHats is WithHSGInstanceTest {
  function test_Multi_OwnerCanAddSignerHats(uint256 count) public {
    vm.assume(count < 100);

    // create and fill an array of signer hats to add, with length = count
    uint256[] memory hats = new uint256[](count);
    for (uint256 i; i < count; ++i) {
      hats[i] = i;
    }

    vm.prank(owner);
    vm.expectEmit(false, false, false, true);
    emit IHatsSignerGate.SignerHatsAdded(hats);

    hatsSignerGate.addSignerHats(hats);
  }

  function test_Multi_OwnerCanAddSignerHats1() public {
    test_Multi_OwnerCanAddSignerHats(1);
  }

  function test_Multi_NonOwnerCannotAddSignerHats() public {
    // create and fill an array of signer hats to add, with length = 1
    uint256[] memory hats = new uint256[](1);
    hats[0] = 1;

    vm.prank(other);
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.addSignerHats(hats);
  }

  function test_revert_locked() public {
    // lock the HSG
    vm.prank(owner);
    hatsSignerGate.lock();

    // create and fill an array of signer hats to add, with length = 1
    uint256[] memory hats = new uint256[](1);
    hats[0] = 1;

    // expect a revert from the locked HSG
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.addSignerHats(hats);
  }
}

contract SettingThresholdConfig is WithHSGInstanceTest {
  function test_happy_absolute(uint120 _min, uint120 _target, uint256 _signerCount) public {
    vm.assume(_min > 0);
    vm.assume(_target >= _min);
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    _addSignersSameHat(_signerCount, signerHat);

    IHatsSignerGate.ThresholdConfig memory newConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: _min,
      target: _target
    });

    vm.expectEmit();
    emit IHatsSignerGate.ThresholdConfigSet(newConfig);
    vm.prank(owner);
    hatsSignerGate.setThresholdConfig(newConfig);

    assertEq(hatsSignerGate.thresholdConfig(), newConfig);

    // check that the safe threshold was updated correctly
    uint256 expectedThreshold;
    if (_signerCount > _target) {
      expectedThreshold = _target;
    } else {
      expectedThreshold = _signerCount;
    }
    assertEq(safe.getThreshold(), expectedThreshold, "incorrect safe threshold");
  }

  function test_happy_proportional(uint120 _min, uint120 _target, uint256 _signerCount) public {
    vm.assume(_min > 0);
    vm.assume(_target < 10_000);
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    _addSignersSameHat(_signerCount, signerHat);

    IHatsSignerGate.ThresholdConfig memory newConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: _min,
      target: _target
    });

    vm.expectEmit();
    emit IHatsSignerGate.ThresholdConfigSet(newConfig);
    vm.prank(owner);
    hatsSignerGate.setThresholdConfig(newConfig);

    assertEq(hatsSignerGate.thresholdConfig(), newConfig);

    // check that the safe threshold was updated correctly
    uint256 target = hatsSignerGate.thresholdConfig().target;
    uint256 min = hatsSignerGate.thresholdConfig().min;
    uint256 expectedThreshold = ((_signerCount * target) + 9999) / 10_000;
    if (expectedThreshold < min) expectedThreshold = min;
    if (expectedThreshold > _signerCount) {
      expectedThreshold = _signerCount;
    }
    assertEq(safe.getThreshold(), expectedThreshold, "incorrect safe threshold");
  }

  function test_revert_absolute_invalidConfig(uint120 _min, uint120 _target) public {
    vm.assume(_min > 0);
    // invalid condition
    vm.assume(_target < _min);

    IHatsSignerGate.ThresholdConfig memory invalidConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: _min,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    vm.prank(owner);
    hatsSignerGate.setThresholdConfig(invalidConfig);

    assertEq(safe.getThreshold(), 1);
  }

  function test_revert_proportional_invalidConfig(uint120 _target) public {
    vm.assume(_target > 10_000);

    IHatsSignerGate.ThresholdConfig memory invalidConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 1,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    vm.prank(owner);
    hatsSignerGate.setThresholdConfig(invalidConfig);

    assertEq(safe.getThreshold(), 1);
  }

  function test_revert_invalidConfigType(uint8 _invalidType) public {
    vm.assume(_invalidType > 1);

    bytes memory invalidConfigBytes = abi.encodePacked(_invalidType, uint120(1), uint120(3));

    bytes memory setThresholdConfigCallData =
      abi.encodeWithSelector(hatsSignerGate.setThresholdConfig.selector, invalidConfigBytes);

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    vm.prank(owner);
    (bool success,) = address(hatsSignerGate).call(setThresholdConfigCallData);
    assertFalse(success);

    assertEq(safe.getThreshold(), 1);
  }

  function test_revert_notOwnerHatWearer() public {
    IHatsSignerGate.ThresholdConfig memory newConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: 1,
      target: 3
    });

    vm.prank(other);
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.setThresholdConfig(newConfig);

    assertEq(hatsSignerGate.thresholdConfig(), thresholdConfig);

    assertEq(safe.getThreshold(), 1);
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    IHatsSignerGate.ThresholdConfig memory newConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: 1,
      target: 3
    });

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setThresholdConfig(newConfig);

    assertEq(safe.getThreshold(), 1);
  }
}

contract AddingSigners is WithHSGInstanceTest {
  function testAddSingleSigner() public {
    _addSignersSameHat(1, signerHat);

    assertEq(safe.getOwners().length, 1);
    assertEq(hatsSignerGate.validSignerCount(), 1);
    assertEq(safe.getOwners()[0], signerAddresses[0]);
    assertEq(safe.getThreshold(), 1);
  }

  function testAddThreeSigners() public {
    _addSignersSameHat(3, signerHat);

    assertEq(hatsSignerGate.validSignerCount(), 3);

    assertEq(safe.getOwners()[0], signerAddresses[2]);
    assertEq(safe.getOwners()[1], signerAddresses[1]);
    assertEq(safe.getOwners()[2], signerAddresses[0]);
    assertEq(safe.getThreshold(), 2);
  }

  function test_Multi_AddSingleSigner() public {
    _addSignersDifferentHats(1, signerHats);

    assertEq(hatsSignerGate.validSignerCount(), 1);
    assertEq(safe.getOwners()[0], signerAddresses[0]);
    assertEq(safe.getThreshold(), 1);
  }

  function test_Multi_AddTwoSigners_DifferentHats() public {
    _addSignersDifferentHats(2, signerHats);

    assertEq(hatsSignerGate.validSignerCount(), 2);
    assertEq(safe.getOwners()[0], signerAddresses[1]);
    assertEq(safe.getOwners()[1], signerAddresses[0]);
    assertEq(safe.getThreshold(), 2);
  }
}

contract ClaimingSigners is WithHSGInstanceTest {
  function test_happy() public {
    _setSignerValidity(signerAddresses[3], signerHat, true);

    vm.prank(signerAddresses[3]);
    hatsSignerGate.claimSigner(signerHat);

    assertEq(safe.getOwners()[0], signerAddresses[3]);
    assertEq(safe.getThreshold(), 1);
    assertEq(safe.getOwners().length, 1);
  }

  function test_revert_alreadyClaimed() public {
    _addSignersSameHat(2, signerHat);

    vm.prank(signerAddresses[1]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignerAlreadyClaimed.selector, signerAddresses[1]));

    hatsSignerGate.claimSigner(signerHat);

    assertEq(hatsSignerGate.validSignerCount(), 2);
  }

  function test_revert_invalidSigner() public {
    _setSignerValidity(signerAddresses[3], signerHat, false);

    vm.prank(signerAddresses[3]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[3]));
    hatsSignerGate.claimSigner(signerHat);
  }

  function test_revert_multi_invalidSigner(uint256 i) public {
    vm.assume(i < 2);
    _setSignerValidity(signerAddresses[3], signerHats[i], false);

    vm.prank(signerAddresses[3]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[3]));
    hatsSignerGate.claimSigner(signerHats[i]);
  }
}

contract RemovingSigners is WithHSGInstanceTest {
  function testCanRemoveInvalidSigner1() public {
    _addSignersSameHat(1, signerHat);

    _setSignerValidity(signerAddresses[0], signerHat, false);

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], address(hatsSignerGate));
    assertEq(hatsSignerGate.validSignerCount(), 0);

    assertEq(safe.getThreshold(), 1);
  }

  function testCanRemoveInvalidSignerWhenMultipleSigners() public {
    _addSignersSameHat(2, signerHat);

    _setSignerValidity(signerAddresses[0], signerHat, false);

    // emit log_uint(hatsSignerGate.signerCount());

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], signerAddresses[1]);
    assertEq(hatsSignerGate.validSignerCount(), 1);

    assertEq(safe.getThreshold(), 1);
  }

  function testCannotRemoveValidSigner() public {
    _addSignersSameHat(1, signerHat);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.StillWearsSignerHat.selector, signerAddresses[0]));

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], signerAddresses[0]);
    assertEq(hatsSignerGate.validSignerCount(), 1);

    assertEq(safe.getThreshold(), 1);
  }

  function test_Multi_CanRemoveInvalidSigner1() public {
    _addSignersDifferentHats(1, signerHats);

    _setSignerValidity(signerAddresses[0], signerHat, false);

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], address(hatsSignerGate));
    assertEq(hatsSignerGate.validSignerCount(), 0);
    assertEq(safe.getThreshold(), 1);
  }

  function test_Multi_CannotRemoveValidSigner() public {
    _addSignersDifferentHats(1, signerHats);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.StillWearsSignerHat.selector, signerAddresses[0]));

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], signerAddresses[0]);
    assertEq(hatsSignerGate.validSignerCount(), 1);

    assertEq(safe.getThreshold(), 1);
  }
}

contract ExecutingTransactions is WithHSGInstanceTest {
  function testExecTxByHatWearers() public {
    _addSignersSameHat(3, signerHat);

    uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);

    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 3);

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
    // confirm it we executed by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(destAddress.balance, transferValue);
    assertEq(safe.nonce(), preNonce + 1);
  }

  function testExecTxByNonHatWearersReverts() public {
    _addSignersSameHat(3, signerHat);

    uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    // uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);
    // emit log_uint(address(safe).balance);
    // create tx to send some eth from safe to wherever
    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 3);

    // removing the hats from 2 signers
    _setSignerValidity(signerAddresses[0], signerHat, false);
    _setSignerValidity(signerAddresses[1], signerHat, false);

    // emit log_uint(address(safe).balance);
    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);

    // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);

    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm it was not executed by checking ETH balance changes
    assertEq(destAddress.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }

  function testExecTxByTooFewOwnersReverts() public {
    // add a legit signer
    _addSignersSameHat(1, signerHat);

    // set up test values
    uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    // uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);

    // have the remaining signer sign it
    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);

    // have them sign it
    bytes memory signatures = _createNSigsForTx(txHash, 1);

    // have the legit signer exec the tx
    vm.prank(signerAddresses[0]);

    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);

    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm it was not executed by checking ETH balance changes
    assertEq(destAddress.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }

  function testExecByLessThanMinThresholdReverts() public {
    _addSignersSameHat(2, signerHat);

    _setSignerValidity(signerAddresses[1], signerHat, false);
    assertEq(safe.getThreshold(), 2, "threshold should be 2");
    assertEq(hatsSignerGate.validSignerCount(), 1, "valid signer count should be 1");

    // set up test values
    // uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    // uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);

    // have the remaining signer sign it
    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);
    // have both signers (1 valid, 1 invalid) sign it
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);
    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function test_Multi_ExecTxByHatWearers() public {
    _addSignersDifferentHats(3, signerHats);

    uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);

    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 3);

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
    // confirm it we executed by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(destAddress.balance, transferValue);
    assertEq(safe.nonce(), preNonce + 1);
  }

  function test_Multi_ExecTxByNonHatWearersReverts() public {
    _addSignersDifferentHats(3, signerHats);

    uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    // uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);
    // emit log_uint(address(safe).balance);
    // create tx to send some eth from safe to wherever
    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 3);

    // removing the hats from 2 signers
    _setSignerValidity(signerAddresses[0], signerHat, false);
    _setSignerValidity(signerAddresses[1], signerHats[1], false);

    // emit log_uint(address(safe).balance);
    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);

    // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);

    safe.execTransaction(
      destAddress,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm it was not executed by checking ETH balance changes
    assertEq(destAddress.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }
}

contract ConstrainingSigners is WithHSGInstanceTest {
  function testCannotDisableModule() public {
    bytes memory disableModuleData =
      abi.encodeWithSignature("disableModule(address,address)", SENTINELS, address(hatsSignerGate));

    _addSignersSameHat(2, signerHat);

    bytes32 txHash = _getTxHash(address(safe), 0, disableModuleData, safe);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(IHatsSignerGate.SignersCannotChangeModules.selector);

    // execute tx
    safe.execTransaction(
      address(safe),
      0,
      disableModuleData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // _executeSafeTxFrom(address(this), disableModuleData, safe);
  }

  function testCannotDisableGuard() public {
    bytes memory disableGuardData = abi.encodeWithSignature("setGuard(address)", address(0x0));

    _addSignersSameHat(2, signerHat);

    bytes32 txHash = _getTxHash(address(safe), 0, disableGuardData, safe);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotDisableThisGuard.selector, address(hatsSignerGate)));
    safe.execTransaction(
      address(safe),
      0,
      disableGuardData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function testCannotIncreaseThreshold() public {
    _addSignersSameHat(3, signerHat);

    uint256 oldThreshold = safe.getThreshold();
    assertEq(oldThreshold, 2);

    // data to increase the threshold data by 1
    bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold + 1);

    bytes32 txHash = _getTxHash(address(safe), 0, changeThresholdData, safe);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignersCannotChangeThreshold.selector));
    safe.execTransaction(
      address(safe),
      0,
      changeThresholdData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function testCannotDecreaseThreshold() public {
    _addSignersSameHat(3, signerHat);

    uint256 oldThreshold = safe.getThreshold();
    assertEq(oldThreshold, 2);

    // data to decrease the threshold data by 1
    bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold - 1);

    bytes32 txHash = _getTxHash(address(safe), 0, changeThresholdData, safe);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignersCannotChangeThreshold.selector));
    safe.execTransaction(
      address(safe),
      0,
      changeThresholdData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function testSignersCannotAddOwners() public {
    _addSignersSameHat(3, signerHat);
    // data for call to add owners
    bytes memory addOwnerData = abi.encodeWithSignature(
      "addOwnerWithThreshold(address,uint256)",
      signerAddresses[9], // newOwner
      safe.getThreshold() // threshold
    );

    bytes32 txHash = _getTxHash(address(safe), 0, addOwnerData, safe);
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignersCannotChangeOwners.selector));
    safe.execTransaction(
      address(safe),
      0,
      addOwnerData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function testSignersCannotRemoveOwners() public {
    _addSignersSameHat(3, signerHat);
    address toRemove = signerAddresses[2];
    // data for call to remove owners
    bytes memory removeOwnerData = abi.encodeWithSignature(
      "removeOwner(address,address,uint256)",
      _findPrevOwner(safe.getOwners(), toRemove), // prevOwner
      toRemove, // owner to remove
      safe.getThreshold() // threshold
    );

    bytes32 txHash = _getTxHash(address(safe), 0, removeOwnerData, safe);
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignersCannotChangeOwners.selector));
    safe.execTransaction(
      address(safe),
      0,
      removeOwnerData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function testSignersCannotSwapOwners() public {
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

    bytes32 txHash = _getTxHash(address(safe), 0, swapOwnerData, safe);
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignersCannotChangeOwners.selector));
    safe.execTransaction(
      address(safe),
      0,
      swapOwnerData,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }
}

contract GuardFunctionAuth is WithHSGInstanceTest {
  function testCannotCallCheckTransactionFromNonSafe() public {
    vm.expectRevert(IHatsSignerGate.NotCalledFromSafe.selector);
    hatsSignerGate.checkTransaction(
      address(0), 0, hex"00", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"00", address(0)
    );
  }

  function testCannotCallCheckAfterExecutionFromNonSafe() public {
    vm.expectRevert(IHatsSignerGate.NotCalledFromSafe.selector);
    hatsSignerGate.checkAfterExecution(hex"00", true);
  }
}

contract DetachingHSG is WithHSGInstanceTest {
  function test_happy() public {
    vm.expectEmit(true, true, true, true);
    emit IHatsSignerGate.Detached();
    vm.prank(owner);
    hatsSignerGate.detachHSG();

    assertFalse(safe.isModuleEnabled(address(hatsSignerGate)), "HSG should not be a module");
    assertEq(_getSafeGuard(address(safe)), address(0), "HSG should not be a guard");
  }

  function test_revert_nonOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(other);
    hatsSignerGate.detachHSG();

    assertTrue(safe.isModuleEnabled(address(hatsSignerGate)), "HSG should still be a module");
    assertEq(_getSafeGuard(address(safe)), (address(hatsSignerGate)), "HSG should still be a guard");
  }

  function test_revert_locked() public {
    // lock the HSG
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.detachHSG();

    assertTrue(safe.isModuleEnabled(address(hatsSignerGate)), "HSG should still be a module");
    assertEq(_getSafeGuard(address(safe)), (address(hatsSignerGate)), "HSG should still be a guard");
  }
}

contract MigratingHSG is WithHSGInstanceTest {
  HatsSignerGate newHSG;

  function setUp() public override {
    super.setUp();

    // create the instance deployer
    DeployInstance instanceDeployer = new DeployInstance();

    // set up the deployment with the same parameters as the existing HSG (except for the nonce)
    instanceDeployer.prepare1(
      address(singletonHatsSignerGate),
      ownerHat,
      signerHats,
      thresholdConfig,
      address(safe),
      false,
      false,
      address(0), // no guard
      new address[](0) // no modules
    );
    instanceDeployer.prepare2(true, 1);

    // deploy the instance
    newHSG = instanceDeployer.run();
  }

  function test_happy_noSignersToMigrate() public {
    vm.expectEmit(true, true, true, true);
    emit IHatsSignerGate.Migrated(address(newHSG));
    vm.prank(owner);
    hatsSignerGate.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));

    assertEq(_getSafeGuard(address(safe)), address(newHSG), "guard should be the new HSG");
    assertFalse(safe.isModuleEnabled(address(hatsSignerGate)), "old HSG should be disabled as module");
    assertTrue(safe.isModuleEnabled(address(newHSG)), "new HSG should be enabled as module");
  }

  function test_happy_claimableFor_signersToMigrate(uint256 _count) public {
    uint256 count = bound(_count, 1, signerAddresses.length);
    // add some signers to the existing HSG
    _addSignersSameHat(count, signerHat);

    // set the claimable for to true for the new HSG
    vm.prank(owner);
    newHSG.setClaimableFor(true);

    // create the migration arrays
    uint256[] memory hatIdsToMigrate = new uint256[](count);
    address[] memory signersToMigrate = new address[](count);
    for (uint256 i; i < count; ++i) {
      hatIdsToMigrate[i] = signerHat;
      signersToMigrate[i] = signerAddresses[i];
    }

    vm.expectEmit(true, true, true, true);
    emit IHatsSignerGate.Migrated(address(newHSG));
    vm.prank(owner);
    hatsSignerGate.migrateToNewHSG(address(newHSG), hatIdsToMigrate, signersToMigrate);

    assertEq(_getSafeGuard(address(safe)), address(newHSG), "guard should be the new HSG");
    assertFalse(safe.isModuleEnabled(address(hatsSignerGate)), "old HSG should be disabled as module");
    assertTrue(safe.isModuleEnabled(address(newHSG)), "new HSG should be enabled as module");

    // check that the signers are now in the new HSG
    for (uint256 i; i < count; ++i) {
      assertTrue(newHSG.isValidSigner(signersToMigrate[i]), "signer should be in the new HSG");
    }
    assertEq(newHSG.validSignerCount(), count, "valid signer count should be correct");
  }

  function test_revert_notClaimableFor_signersToMigrate(uint256 _count) public {
    uint256 count = bound(_count, 1, signerAddresses.length);
    // add some signers to the existing HSG
    _addSignersSameHat(count, signerHat);

    // don't set the claimable for to true for the new HSG

    // create the migration arrays
    uint256[] memory hatIdsToMigrate = new uint256[](count);
    address[] memory signersToMigrate = new address[](count);
    for (uint256 i; i < count; ++i) {
      hatIdsToMigrate[i] = signerHat;
      signersToMigrate[i] = signerAddresses[i];
    }

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    vm.prank(owner);
    hatsSignerGate.migrateToNewHSG(address(newHSG), hatIdsToMigrate, signersToMigrate);

    assertEq(_getSafeGuard(address(safe)), address(hatsSignerGate), "guard should be the old HSG");
    assertTrue(safe.isModuleEnabled(address(hatsSignerGate)), "old HSG should be enabled as module");
    assertFalse(safe.isModuleEnabled(address(newHSG)), "new HSG should not be enabled as module");

    // check that the signers are now in the new HSG
    for (uint256 i; i < count; ++i) {
      assertFalse(newHSG.isValidSigner(signersToMigrate[i]), "signer should not be in the new HSG");
    }
    assertEq(newHSG.validSignerCount(), 0, "valid signer count should be 0");
  }

  function test_revert_nonOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(other);
    hatsSignerGate.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));
  }
}

contract SettingClaimableFor is WithHSGInstanceTest {
  function test_happy(bool _claimableFor) public {
    vm.expectEmit(true, true, true, true);
    emit IHatsSignerGate.ClaimableForSet(_claimableFor);
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(_claimableFor);

    assertEq(hatsSignerGate.claimableFor(), _claimableFor, "incorrectclaimableFor");
  }

  function test_revert_nonOwner() public {
    bool currentClaimableFor = hatsSignerGate.claimableFor();

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(other);
    hatsSignerGate.setClaimableFor(true);

    assertEq(hatsSignerGate.claimableFor(), currentClaimableFor, "claimableFor should not be changed");
  }

  function test_revert_locked() public {
    bool currentClaimableFor = hatsSignerGate.claimableFor();

    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    assertEq(hatsSignerGate.claimableFor(), currentClaimableFor, "claimableFor should not be changed");
  }
}

contract ClaimingSignerFor is WithHSGInstanceTest {
  function test_happy() public {
    _setSignerValidity(signerAddresses[0], signerHat, true);

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[0]);

    assertEq(hatsSignerGate.validSignerCount(), 1);
    assertEq(safe.getOwners().length, 1);
  }

  function test_happy_alreadyOwnerNotRegistered() public {
    // add a signer directly to the safe by pranking the safe
    vm.prank(address(safe));
    safe.addOwnerWithThreshold(signerAddresses[0], 1);

    // set the signer's validity
    _setSignerValidity(signerAddresses[0], signerHat, true);

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // claim the signer
    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[0]);

    assertEq(hatsSignerGate.validSignerCount(), 1, "valid signer count should be 1");
    // owner count should be 2 since the hsg instance is still an owner
    assertEq(safe.getOwners().length, 2, "owner count should be 2");
  }

  function test_revert_notClaimableFor() public {
    _setSignerValidity(signerAddresses[0], signerHat, true);

    // set the claimable for to true and then undo it
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(false);

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[0]);

    assertEq(hatsSignerGate.validSignerCount(), 0);
    assertEq(safe.getOwners().length, 1);
  }

  function test_revert_alreadyClaimed() public {
    _setSignerValidity(signerAddresses[0], signerHat, true);

    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[0]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignerAlreadyClaimed.selector, signerAddresses[0]));
    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[0]);

    assertEq(hatsSignerGate.validSignerCount(), 1);
    assertEq(safe.getOwners().length, 1);
  }

  function test_revert_invalidSignerHat() public {
    uint256 invalidSignerHat = signerHat + 1;
    _setSignerValidity(signerAddresses[0], signerHat, true);

    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, invalidSignerHat));
    hatsSignerGate.claimSignerFor(invalidSignerHat, signerAddresses[0]);

    assertEq(hatsSignerGate.validSignerCount(), 0);
    assertEq(safe.getOwners().length, 1);
  }

  function test_revert_invalidSigner() public {
    _setSignerValidity(signerAddresses[0], signerHat, false);

    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[1]));
    hatsSignerGate.claimSignerFor(signerHat, signerAddresses[1]);

    assertEq(hatsSignerGate.validSignerCount(), 0);
    assertEq(safe.getOwners().length, 1);
  }
}

contract ClaimingSignersFor is WithHSGInstanceTest {
  function test_startingEmpty_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    // claim the signers
    hatsSignerGate.claimSignersFor(hatIds, claimers);

    assertEq(hatsSignerGate.validSignerCount(), _signerCount, "incorrect valid signer count");
    assertEq(safe.getOwners().length, _signerCount, "incorrect owner count");
  }

  function test_startingWith1Signer_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // add one signer to get rid of the placeholder owner
    _addSignersSameHat(1, signerHat);
    assertEq(hatsSignerGate.validSignerCount(), 1, "valid signer count should be 1");
    assertEq(safe.getOwners().length, 1, "owner count should be 1");

    // create the necessary arrays, starting with the next signer
    address[] memory claimers = new address[](_signerCount - 1);
    uint256[] memory hatIds = new uint256[](_signerCount - 1);
    for (uint256 i; i < _signerCount - 1; ++i) {
      claimers[i] = signerAddresses[i + 1];
      hatIds[i] = signerHat;
    }

    // claim the signers
    hatsSignerGate.claimSignersFor(hatIds, claimers);

    assertEq(hatsSignerGate.validSignerCount(), _signerCount, "incorrect valid signer count");
    assertEq(safe.getOwners().length, _signerCount, "incorrect owner count");
  }

  function test_alreadyOwnerNotRegistered_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // add _signerCount signers directly to the safe by pranking the safe
    for (uint256 i; i < _signerCount; ++i) {
      vm.prank(address(safe));
      safe.addOwnerWithThreshold(signerAddresses[i], 1);
    }

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    // claim the signers
    hatsSignerGate.claimSignersFor(hatIds, claimers);

    assertEq(hatsSignerGate.validSignerCount(), _signerCount, "incorrect valid signer count");
    // owner count should be 1 more than the number of valid signers since the hsg instance is still an owner
    assertEq(safe.getOwners().length, _signerCount + 1, "should be 1 more than the number of valid signers");
  }

  function test_revert_notClaimableFor(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true and then undo it
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(false);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    hatsSignerGate.claimSignersFor(hatIds, claimers);

    assertEq(hatsSignerGate.validSignerCount(), 0, "incorrect valid signer count");
    assertEq(safe.getOwners().length, 1, "incorrect owner count");
  }

  function test_revert_invalidSignerHat(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);
    uint256 invalidSignerHat = signerHat + 1;

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = invalidSignerHat;
    }

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, invalidSignerHat));
    hatsSignerGate.claimSignersFor(hatIds, claimers);
  }

  function test_revert_invalidSigner(uint256 _signerCount, uint256 _invalidSignerIndex) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);
    _invalidSignerIndex = bound(_invalidSignerIndex, 0, _signerCount - 1);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      if (i == _invalidSignerIndex) {
        _setSignerValidity(signerAddresses[i], signerHat, false);
      } else {
        _setSignerValidity(signerAddresses[i], signerHat, true);
      }
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    vm.expectRevert(
      abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[_invalidSignerIndex])
    );
    hatsSignerGate.claimSignersFor(hatIds, claimers);
  }

  function test_revert_alreadyClaimed(uint256 _signerCount, uint256 _alreadyClaimedIndex) public {
    _signerCount = bound(_signerCount, 2, signerAddresses.length);
    _alreadyClaimedIndex = bound(_alreadyClaimedIndex, 0, _signerCount - 1);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // have the _alreadyClaimedIndex signer claim their signer permissions
    address claimedSigner = signerAddresses[_alreadyClaimedIndex];
    vm.prank(claimedSigner);
    hatsSignerGate.claimSigner(signerHat);

    // create the arrays for the remaining signers
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    vm.expectRevert(
      abi.encodeWithSelector(IHatsSignerGate.SignerAlreadyClaimed.selector, signerAddresses[_alreadyClaimedIndex])
    );
    hatsSignerGate.claimSignersFor(hatIds, claimers);
  }

  function test_revert_invalidArrayLength(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    hatsSignerGate.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount - 1);
    for (uint256 i; i < _signerCount - 1; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }
    claimers[_signerCount - 1] = signerAddresses[_signerCount - 1];

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidArrayLength.selector));
    hatsSignerGate.claimSignersFor(hatIds, claimers);
  }
}

contract SettingOwnerHat is WithHSGInstanceTest {
  uint256 newOwnerHat = ownerHat + 1;

  function test_happy() public {
    vm.prank(owner);
    hatsSignerGate.setOwnerHat(newOwnerHat);

    assertEq(hatsSignerGate.ownerHat(), newOwnerHat, "owner hat should be new");
  }

  function test_revert_notOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.setOwnerHat(newOwnerHat);

    assertEq(hatsSignerGate.ownerHat(), ownerHat, "owner hat should be old");
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setOwnerHat(newOwnerHat);

    assertEq(hatsSignerGate.ownerHat(), ownerHat, "owner hat should be old");
  }
}

contract SettingHSGGuard is WithHSGInstanceTest {
  function test_happy() public {
    vm.expectEmit(true, true, true, true);
    emit GuardableUnowned.ChangedGuard(address(tstGuard));
    vm.prank(owner);
    hatsSignerGate.setGuard(address(tstGuard));

    assertEq(hatsSignerGate.getGuard(), address(tstGuard), "guard should be tstGuard");
  }

  function test_removeGuard() public {
    address emptyGuard = address(0);
    vm.expectEmit(true, true, true, true);
    emit GuardableUnowned.ChangedGuard(emptyGuard);
    vm.prank(owner);
    hatsSignerGate.setGuard(emptyGuard);

    assertEq(hatsSignerGate.getGuard(), emptyGuard, "guard should be empty");
  }

  function test_revert_notOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.setGuard(address(tstGuard));

    assertEq(hatsSignerGate.getGuard(), address(0), "guard should be empty");
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setGuard(address(tstGuard));

    assertEq(hatsSignerGate.getGuard(), address(0), "guard should be empty");
  }
}

contract HSGGuarding is WithHSGInstanceTest {
  uint256 public disallowedValue = 1337;
  uint256 public goodValue = 9_000_000_000;
  address public recipient = makeAddr("recipient");
  uint256 public signerCount = 2;

  function setUp() public override {
    super.setUp();

    // set it on our hsg instance
    vm.prank(owner);
    hatsSignerGate.setGuard(address(tstGuard));
    assertEq(hatsSignerGate.getGuard(), address(tstGuard), "guard should be tstGuard");

    // deal the safe some eth
    deal(address(safe), 1 ether);

    // add signerCount number of signers
    _addSignersSameHat(signerCount, signerHat);

    address[] memory owners = safe.getOwners();
    assertEq(owners.length, signerCount, "owners should be signerCount");
  }

  /// @dev a successful transaction should hit the tstGuard's checkTransaction and checkAfterExecution funcs
  function test_executed() public {
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = goodValue;
    uint256 postValue = preValue - transferValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the `sender` param to be address(0) because the sender param from hsg.checkTransaction is empty
    vm.expectEmit();
    emit TestGuard.PreChecked(address(0));
    vm.expectEmit();
    emit TestGuard.PostChecked(true);

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
    assertEq(safe.nonce(), preNonce + 1);
  }

  // the test guard should revert in checkTransaction
  function test_revert_checkTransaction() public {
    // we make this happen by using a bad value in the safe.execTransaction call
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = disallowedValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the test guard to revert in checkTransaction
    vm.expectRevert("Cannot send 1337");

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }

  // the test guard should revert in checkAfterExecution
  function test_revert_checkAfterExecution() public {
    // we make this happen by setting the test guard to disallow execution
    tstGuard.disallowExecution();

    // craft a basic eth transfer tx
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = goodValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the test guard to revert in checkTransaction
    vm.expectRevert("Reverted in checkAfterExecution");

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }
}

contract EnablingHSGModules is WithHSGInstanceTest {
  address newModule = tstModule1;

  function test_happy() public {
    vm.expectEmit(true, true, true, true);
    emit IAvatar.EnabledModule(newModule);
    vm.prank(owner);
    hatsSignerGate.enableModule(newModule);

    assertTrue(hatsSignerGate.isModuleEnabled(newModule), "new module should be enabled");
  }

  function test_revert_notOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.enableModule(newModule);

    assertFalse(hatsSignerGate.isModuleEnabled(newModule), "new module should not be enabled");
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.enableModule(newModule);

    assertFalse(hatsSignerGate.isModuleEnabled(newModule), "new module should not be enabled");
  }
}

contract DisablingHSGModules is WithHSGInstanceTest {
  address newModule = tstModule1;

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    hatsSignerGate.enableModule(newModule);

    assertTrue(hatsSignerGate.isModuleEnabled(newModule), "new module should be enabled");
  }

  function test_happy() public {
    vm.expectEmit(true, true, true, true);
    emit IAvatar.DisabledModule(newModule);
    vm.prank(owner);
    // since newModule is the only enabled module, prevModule is the SENTINEL
    hatsSignerGate.disableModule({ prevModule: SENTINELS, module: newModule });

    assertFalse(hatsSignerGate.isModuleEnabled(newModule), "new module should be disabled");
  }

  function test_revert_notOwner() public {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.disableModule({ prevModule: SENTINELS, module: newModule });

    assertTrue(hatsSignerGate.isModuleEnabled(newModule), "new module should still be enabled");
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.disableModule({ prevModule: SENTINELS, module: newModule });

    assertTrue(hatsSignerGate.isModuleEnabled(newModule), "new module should still be enabled");
  }
}

contract ExecutingFromModuleViaHSG is WithHSGInstanceTest {
  address newModule = tstModule1;
  address recipient = makeAddr("recipient");

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    hatsSignerGate.enableModule(newModule);

    // deal the safe some eth
    deal(address(safe), 1 ether);
  }

  function test_happy_executionSuccess() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;
    uint256 postValue = preValue - transferValue;

    // have the new module submit/exec the tx, expecting a success event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleSuccess(address(hatsSignerGate));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleSuccess(newModule);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModule(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
  }

  function test_happy_executionFailure() public {
    // craft a call to a function that doesn't exist on a contract (we'll use Hats.sol)
    bytes memory badCall = abi.encodeWithSignature("badCall()");

    // have the new module submit/exec the tx, expecting a failure event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleFailure(address(hatsSignerGate));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleFailure(newModule);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModule(address(hats), 0, badCall, Enum.Operation.Call);
  }

  function test_revert_notModule() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;

    // have a non-module submit/exec the tx, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(ModifierUnowned.NotAuthorized.selector, other));
    vm.prank(other);
    hatsSignerGate.execTransactionFromModule(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
  }

  function test_revert_moduleCannotCallSafe() public {
    uint256 transferValue = 0.3 ether;
    // try to send to the safe, expecting a revert
    vm.expectRevert(IHatsSignerGate.ModulesCannotCallSafe.selector);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModule(address(safe), transferValue, hex"00", Enum.Operation.Call);
  }
}

contract ExecutingFromModuleReturnDataViaHSG is WithHSGInstanceTest {
  address newModule = tstModule1;
  address recipient = makeAddr("recipient");

  function setUp() public override {
    super.setUp();

    // enable a new module
    vm.prank(owner);
    hatsSignerGate.enableModule(newModule);

    // deal the safe some eth
    deal(address(safe), 1 ether);
  }

  function test_happy_executionSuccess() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;
    uint256 postValue = preValue - transferValue;

    // have the new module submit/exec the tx, expecting a success event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleSuccess(address(hatsSignerGate));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleSuccess(newModule);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModuleReturnData(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
  }

  function test_happy_executionFailure() public {
    // craft a call to a function that doesn't exist on a contract (we'll use Hats.sol)
    bytes memory badCall = abi.encodeWithSignature("badCall()");

    // have the new module submit/exec the tx, expecting a failure event emission from both hsg and the newModule
    vm.expectEmit();
    emit IModuleManager.ExecutionFromModuleFailure(address(hatsSignerGate));
    vm.expectEmit();
    emit IAvatar.ExecutionFromModuleFailure(newModule);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModuleReturnData(address(hats), 0, badCall, Enum.Operation.Call);
  }

  function test_revert_notModule() public {
    uint256 preValue = address(safe).balance;
    uint256 transferValue = 0.3 ether;

    // have a non-module submit/exec the tx, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(ModifierUnowned.NotAuthorized.selector, other));
    vm.prank(other);
    hatsSignerGate.execTransactionFromModuleReturnData(recipient, transferValue, hex"00", Enum.Operation.Call);

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
  }

  function test_revert_moduleCannotCallSafe() public {
    uint256 transferValue = 0.3 ether;
    // try to send to the safe, expecting a revert
    vm.expectRevert(IHatsSignerGate.ModulesCannotCallSafe.selector);
    vm.prank(newModule);
    hatsSignerGate.execTransactionFromModuleReturnData(address(safe), transferValue, hex"00", Enum.Operation.Call);
  }
}
