// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/Test.sol";
import { Enum, ISafe, ModuleProxyFactory, TestSuite, WithHSGInstanceTest, HatsSignerGate } from "./TestSuite.sol";
import { IHatsSignerGate, HSGEvents } from "../src/interfaces/IHatsSignerGate.sol";

contract Deployment is TestSuite {
  // errors from dependencies
  error InvalidInitialization();

  function test_onlyHSG(bool _locked) public {
    // deploy safe with this contract as the single owner
    address[] memory owners = new address[](1);
    owners[0] = address(this);
    ISafe testSafe = _deploySafe(owners, 1, TEST_SALT_NONCE);

    hatsSignerGate = _deployHSG({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _minThreshold: minThreshold,
      _targetThreshold: targetThreshold,
      _maxSigners: maxSigners,
      _safe: address(testSafe),
      _expectedError: bytes4(0), // no expected error
      _locked: _locked,
      _verbose: false
    });

    assertEq(hatsSignerGate.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(hatsSignerGate.minThreshold(), minThreshold);
    assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
    assertEq(hatsSignerGate.maxSigners(), maxSigners);
    assertEq(address(hatsSignerGate.HATS()), address(hats));
    assertEq(address(hatsSignerGate.safe()), address(testSafe));
    assertEq(hatsSignerGate.version(), version);
    assertEq(address(hatsSignerGate.implementation()), address(singletonHatsSignerGate));
    assertEq(hatsSignerGate.locked(), _locked);
  }

  function test_andSafe(bool _locked) public {
    (hatsSignerGate, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _minThreshold: minThreshold,
      _targetThreshold: targetThreshold,
      _maxSigners: maxSigners,
      _locked: _locked,
      _verbose: false
    });

    assertEq(hatsSignerGate.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(hatsSignerGate.minThreshold(), minThreshold);
    assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
    assertEq(hatsSignerGate.maxSigners(), maxSigners);
    assertEq(address(hatsSignerGate.HATS()), address(hats));
    assertEq(address(hatsSignerGate.safe()), address(safe));
    assertEq(hatsSignerGate.version(), version);
    assertEq(address(hatsSignerGate.implementation()), address(singletonHatsSignerGate));
    assertEq(_getSafeGuard(address(safe)), address(hatsSignerGate));
    assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));
    assertEq(safe.getOwners()[0], address(hatsSignerGate));
    assertEq(hatsSignerGate.locked(), _locked);
  }

  function test_revert_onlyHSG_existingSafeHasModules() public {
    // deploy safe with this contract as the single owner
    address[] memory owners = new address[](1);
    owners[0] = address(this);
    ISafe testSafe = _deploySafe(owners, 1, TEST_SALT_NONCE);

    // attach a module to the safe
    address dummyModule = makeAddr("dummyModule");
    bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", dummyModule);
    _executeSafeTxFrom(address(this), addModuleData, testSafe);
    assertTrue(testSafe.isModuleEnabled(dummyModule), "test safe does not have dummy module enabled");

    // deploy an instance of HSG, expecting a revert from a failed initialization
    hatsSignerGate = _deployHSG({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _minThreshold: minThreshold,
      _targetThreshold: targetThreshold,
      _maxSigners: maxSigners,
      _safe: address(testSafe),
      _expectedError: ModuleProxyFactory.FailedInitialization.selector,
      _locked: false,
      _verbose: false
    });
  }

  function test_revert_reinitializeImplementation() public {
    bytes memory initializeParams = abi.encode(
      ownerHat,
      signerHats,
      address(safe),
      minThreshold,
      targetThreshold,
      maxSigners,
      false,
      address(singletonHatsSignerGate)
    );
    vm.expectRevert(InvalidInitialization.selector);
    singletonHatsSignerGate.setUp(initializeParams);
  }

  // TODO bring back this test?
  // function test_revert_onlyHSG_validSignerCountExceedsMaxSigners() public {
  //     // deploy safe with more owners than maxSigners, and mint hats to each owner so that they're valid signers
  //     address[] memory owners = new address[](maxSigners + 1);
  //     for (uint256 i = 0; i < maxSigners + 1; i++) {
  //         owners[i] = signerAddresses[i];
  //         vm.prank(org);
  //         hats.mintHat(signerHats[0], owners[i]);
  //     }
  //     console2.log("signerHats[0]", signerHats[0]);
  //     ISafe testSafe = _deploySafe(owners, 1, TEST_SALT_NONCE);

  //     // deploy an instance of HSG, expecting a revert from a failed initialization
  //     hatsSignerGate = _deployHSG(
  //         ownerHat,
  //         signerHats,
  //         minThreshold,
  //         targetThreshold,
  //         maxSigners,
  //         address(testSafe),
  //         ModuleProxyFactory.FailedInitialization.selector,
  //         false
  //     );
  // }
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
    emit HSGEvents.SignerHatsAdded(hats);

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

contract SettingTargetThreshold is WithHSGInstanceTest {
  function testSetTargetThreshold() public {
    _addSignersSameHat(1, signerHat);

    vm.prank(owner);
    vm.expectEmit(false, false, false, true);
    emit HSGEvents.TargetThresholdSet(3);
    hatsSignerGate.setTargetThreshold(3);

    assertEq(hatsSignerGate.targetThreshold(), 3);
    assertEq(safe.getThreshold(), 1);
  }

  function testSetTargetThreshold3of4() public {
    _addSignersSameHat(4, signerHat);

    vm.prank(owner);
    vm.expectEmit(false, false, false, true);
    emit HSGEvents.TargetThresholdSet(3);

    hatsSignerGate.setTargetThreshold(3);

    assertEq(hatsSignerGate.targetThreshold(), 3);
    assertEq(safe.getThreshold(), 3);
  }

  function testSetTargetThreshold4of4() public {
    _addSignersSameHat(4, signerHat);

    vm.prank(owner);
    vm.expectEmit(false, false, false, true);
    emit HSGEvents.TargetThresholdSet(4);

    hatsSignerGate.setTargetThreshold(4);

    assertEq(hatsSignerGate.targetThreshold(), 4);
    assertEq(safe.getThreshold(), 4);
  }

  function testNonOwnerHatWearerCannotSetTargetThreshold() public {
    vm.prank(other);
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.setTargetThreshold(3);

    assertEq(hatsSignerGate.targetThreshold(), 2);
    assertEq(safe.getThreshold(), 1);
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(3);
  }
}

contract SettingMinThreshold is WithHSGInstanceTest {
  function testSetMinThreshold() public {
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(3);

    vm.expectEmit(false, false, false, true);
    emit HSGEvents.MinThresholdSet(3);

    vm.prank(owner);
    hatsSignerGate.setMinThreshold(3);

    assertEq(hatsSignerGate.minThreshold(), 3);
  }

  function testSetInvalidMinThreshold() public {
    vm.prank(owner);
    vm.expectRevert(IHatsSignerGate.InvalidMinThreshold.selector);
    hatsSignerGate.setMinThreshold(3);
  }

  function testNonOwnerCannotSetMinThreshold() public {
    vm.prank(other);
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    hatsSignerGate.setMinThreshold(1);

    assertEq(hatsSignerGate.minThreshold(), 2);
  }

  function test_revert_locked() public {
    vm.prank(owner);
    hatsSignerGate.lock();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(owner);
    hatsSignerGate.setMinThreshold(3);
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

  function testAddTooManySigners() public {
    _addSignersSameHat(5, signerHat);

    _setSignerValidity(signerAddresses[5], signerHat, true);
    vm.expectRevert(IHatsSignerGate.MaxSignersReached.selector);
    vm.prank(signerAddresses[5]);
    // this call should fail
    hatsSignerGate.claimSigner(signerHat);

    assertEq(hatsSignerGate.validSignerCount(), 5);

    assertEq(safe.getOwners()[0], signerAddresses[4]);
    assertEq(safe.getOwners()[1], signerAddresses[3]);
    assertEq(safe.getOwners()[2], signerAddresses[2]);
    assertEq(safe.getOwners()[3], signerAddresses[1]);
    assertEq(safe.getOwners()[4], signerAddresses[0]);
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
  function testClaimSigner() public {
    _setSignerValidity(signerAddresses[3], signerHat, true);

    vm.prank(signerAddresses[3]);
    hatsSignerGate.claimSigner(signerHat);

    assertEq(safe.getOwners()[0], signerAddresses[3]);
    assertEq(safe.getThreshold(), 1);
    assertEq(safe.getOwners().length, 1);
  }

  function testOwnerClaimSignerReverts() public {
    _addSignersSameHat(2, signerHat);

    vm.prank(signerAddresses[1]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.SignerAlreadyClaimed.selector, signerAddresses[1]));

    hatsSignerGate.claimSigner(signerHat);

    assertEq(hatsSignerGate.validSignerCount(), 2);
  }

  function testNonHatWearerCannotClaimSigner() public {
    _setSignerValidity(signerAddresses[3], signerHat, false);

    vm.prank(signerAddresses[3]);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[3]));
    hatsSignerGate.claimSigner(signerHat);
  }

  function test_Multi_NonHatWearerCannotClaimSigner(uint256 i) public {
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

  function testCanRemoveInvalidSignerAfterReconcile2Signers() public {
    _addSignersSameHat(2, signerHat);

    _setSignerValidity(signerAddresses[0], signerHat, false);

    hatsSignerGate.reconcileSignerCount();
    assertEq(hatsSignerGate.validSignerCount(), 1);

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 1);
    assertEq(safe.getOwners()[0], signerAddresses[1]);
    assertEq(hatsSignerGate.validSignerCount(), 1);

    assertEq(safe.getThreshold(), 1);
  }

  function testCanRemoveInvalidSignerAfterReconcile3PLusSigners() public {
    _addSignersSameHat(3, signerHat);

    _setSignerValidity(signerAddresses[0], signerHat, false);

    hatsSignerGate.reconcileSignerCount();
    assertEq(hatsSignerGate.validSignerCount(), 2);

    hatsSignerGate.removeSigner(signerAddresses[0]);

    assertEq(safe.getOwners().length, 2);
    assertEq(safe.getOwners()[0], signerAddresses[2]);
    assertEq(safe.getOwners()[1], signerAddresses[1]);
    assertEq(hatsSignerGate.validSignerCount(), 2);

    assertEq(safe.getThreshold(), 2);
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
    // emit log_uint(address(safe).balance);
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
    vm.expectRevert(IHatsSignerGate.InvalidSigners.selector);

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

    vm.expectRevert(
      abi.encodeWithSelector(
        IHatsSignerGate.BelowMinThreshold.selector, hatsSignerGate.minThreshold(), safe.getOwners().length
      )
    );

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
    assertEq(safe.getThreshold(), 2);

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
    // have them sign it
    bytes memory signatures = _createNSigsForTx(txHash, 1);

    hatsSignerGate.reconcileSignerCount();
    assertEq(safe.getThreshold(), 1);

    // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
    vm.expectRevert(IHatsSignerGate.InvalidSigners.selector);
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
    vm.expectRevert(IHatsSignerGate.InvalidSigners.selector);

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

contract ReconcilingSignerCount is WithHSGInstanceTest {
// function testReconcileSignerCount() public {
//     _setSignerValidity(signerAddresses[1], signerHat, false);
//     _setSignerValidity(signerAddresses[2], signerHat, false);
//     _setSignerValidity(signerAddresses[3], signerHat, false);
//     // add 3 more safe owners the old fashioned way
//     // 1
//     bytes memory addOwnersData1 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)",
// signerAddresses[1], 1);

//     // _setSignerValidity(address(this), signerHat, true);
//     vm.prank(address(hatsSignerGate));

//     safe.execTransactionFromModule(
//         address(safe), // to
//         0, // value
//         addOwnersData1, // data
//         Enum.Operation.Call // operation
//     );

//     // 2
//     bytes memory addOwnersData2 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)",
// signerAddresses[2], 1);

//     // _setSignerValidity(address(this), signerHat, true);
//     vm.prank(address(hatsSignerGate));

//     safe.execTransactionFromModule(
//         address(safe), // to
//         0, // value
//         addOwnersData2, // data
//         Enum.Operation.Call // operation
//     );

//     // 3
//     bytes memory addOwnersData3 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)",
// signerAddresses[3], 1);

//     // _setSignerValidity(address(this), signerHat, true);
//     vm.prank(address(hatsSignerGate));

//     safe.execTransactionFromModule(
//         address(safe), // to
//         0, // value
//         addOwnersData3, // data
//         Enum.Operation.Call // operation
//     );

//     assertEq(hatsSignerGate.validSignerCount(), 0);

//     // set only two of them as valid signers
//     _setSignerValidity(signerAddresses[0], signerHat, true);
//     _setSignerValidity(signerAddresses[1], signerHat, true);

//     // do the reconcile
//     hatsSignerGate.reconcileSignerCount();

//     assertEq(hatsSignerGate.validSignerCount(), 2, "first signer count check");
//     assertEq(safe.getThreshold(), 2, "first threshold check");

//     // now we can remove both the invalid signers with no changes to hatsSignerCount
//     _setSignerValidity(signerAddresses[2], signerHat, false);
//     hatsSignerGate.removeSigner(signerAddresses[2]);
//     _setSignerValidity(signerAddresses[3], signerHat, false);
//     hatsSignerGate.removeSigner(signerAddresses[3]);

//     assertEq(hatsSignerGate.validSignerCount(), 2, "second signer count check");
//     assertEq(safe.getThreshold(), 2, "second threshold check");
// }
}
