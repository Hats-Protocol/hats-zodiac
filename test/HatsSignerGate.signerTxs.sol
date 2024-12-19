// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, WithHSGInstanceTest } from "./TestSuite.t.sol";
import { IHats, IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { TestGuard } from "./mocks/TestGuard.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";

contract ExecutingTransactions is WithHSGInstanceTest {
  event ExecutionSuccess(bytes32 indexed txHash, uint256 payment);

  address payable recipient1 = payable(makeAddr("recipient1"));
  address payable recipient2 = payable(makeAddr("recipient2"));

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);

    // have them sign it
    bytes memory signatures = _createNSigsForTx(txHash, 1);

    // have the legit signer exec the tx
    vm.prank(signerAddresses[0]);

    vm.expectRevert(IHatsSignerGate.ThresholdTooLow.selector);

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
    assertEq(instance.validSignerCount(), 1, "valid signer count should be 1");

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);
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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);

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

  function test_happy_delegateCall() public {
    _addSignersSameHat(2, signerHat);

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

    // execute the multisend to each of the default delegatecall targets
    for (uint256 i = 0; i < defaultDelegatecallTargets.length; i++) {
      // get the tx hash
      bytes32 txHash = _getTxHash(defaultDelegatecallTargets[i], 0, Enum.Operation.DelegateCall, multisendCall, safe);

      // have the signers sign it
      bytes memory signatures = _createNSigsForTx(txHash, 2);

      // have one of the signers exec the multisend call
      vm.expectEmit();
      emit ExecutionSuccess(txHash, 0);
      vm.prank(signerAddresses[0]);
      safe.execTransaction(
        defaultDelegatecallTargets[i],
        0,
        multisendCall,
        Enum.Operation.DelegateCall,
        0,
        0,
        0,
        address(0),
        payable(address(0)),
        signatures
      );
    }
  }

  function test_happy_multiSend() public {
    uint256 firstSendAmount = 0.1 ether;
    uint256 secondSendAmount = 0.2 ether;

    // add 3 signers
    _addSignersSameHat(3, signerHat);

    // deal the safe some ETH
    deal(address(safe), 1 ether);

    // craft a multisend action to send eth twice
    bytes memory packedCalls = abi.encodePacked(
      // 1) first send
      uint8(0), // 0 for call; 1 for delegatecall
      address(recipient1), // to
      uint256(firstSendAmount), // value
      uint256(0), // data length
      hex"", // data
      // 2) second send
      uint8(0), // 0 for call; 1 for delegatecall
      address(recipient2), // to
      uint256(secondSendAmount), // value
      uint256(0), // data length
      hex"" // data
    );

    bytes memory multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the tx hash
    bytes32 safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0],
      0, // value
      multiSendData, // data
      Enum.Operation.DelegateCall, // operation
      0, // safeTxGas
      0, // baseGas
      0, // gasPrice
      address(0), // gasToken
      payable(address(0)), // refundReceiver
      safe.nonce() // nonce
    );

    // sufficient signers sign it
    bytes memory sigs = _createNSigsForTx(safeTxHash, 2);

    // execute the tx
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      sigs
    );

    // confirm correct balances
    assertEq(recipient1.balance, firstSendAmount, "wrong recipient1 balance");
    assertEq(recipient2.balance, secondSendAmount, "wrong recipient2 balance");
  }

  function test_happy_batchMultiSend(uint256 _batchSize) public {
    // construct an N-action multisend that will call execTransaction a random number of times
    uint256 batchSize = bound(_batchSize, 1, 50);
    // ensure the safe has enough ETH to cover the batch
    deal(address(safe), batchSize * 1 ether);

    // add 3 signers
    _addSignersSameHat(3, signerHat);

    uint256 sendAmount = 0.1 ether;
    bytes32[] memory txHashes = new bytes32[](batchSize);
    bytes[] memory signatures = new bytes[](batchSize);
    bytes[] memory actionData = new bytes[](batchSize);
    bytes memory packedCalls;

    uint256 startingNonce = safe.nonce();

    for (uint256 i; i < batchSize; i++) {
      // get the tx hash for each action
      txHashes[i] = safe.getTransactionHash(
        recipient1,
        sendAmount, // value
        hex"", // data
        Enum.Operation.Call, // operation
        0, // safeTxGas
        0, // baseGas
        0, // gasPrice
        address(0), // gasToken
        payable(address(0)), // refundReceiver
        startingNonce + i // nonce needs to increment for each tx
      );

      // sufficient signers sign each action
      signatures[i] = _createNSigsForTx(txHashes[i], 2);

      // encode each Safe.execTransaction call
      actionData[i] = abi.encodeWithSignature(
        "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
        recipient1,
        sendAmount, // value
        hex"",
        Enum.Operation.Call,
        0,
        0,
        0,
        address(0),
        payable(address(0)),
        signatures[i]
      );

      // encode the action data for multiSend
      bytes memory packedCall = abi.encodePacked(
        uint8(0), // 0 for call; 1 for delegatecall
        address(safe), // to
        uint256(0), // value
        uint256(actionData[i].length), // data length
        actionData[i] // data
      );

      // append the action data into a multisend call
      packedCalls = abi.encodePacked(packedCalls, packedCall);
    }

    // execute the multisend
    MultiSend(defaultDelegatecallTargets[0]).multiSend(packedCalls);

    // confirm correct balances
    assertEq(recipient1.balance, sendAmount * batchSize, "wrong recipient1 balance");
  }

  function test_happy_multiSend2() public {
    test_happy_batchMultiSend(2);
  }

  function test_happy_multiSend10() public {
    test_happy_batchMultiSend(10);
  }

  function test_happy_multiSend50() public {
    test_happy_batchMultiSend(50);
  }
}

contract ConstrainingSigners is WithHSGInstanceTest {
  function test_revert_delegateCallTargetNotEnabled() public {
    address target = makeAddr("target");

    _addSignersSameHat(2, signerHat);

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

    // get the tx hash
    bytes32 txHash = _getTxHash(target, 0, Enum.Operation.DelegateCall, multisendCall, safe);

    // have the signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    // have one of the signers exec the multisend call
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      target, 0, multisendCall, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), signatures
    );
  }

  function testCannotDisableModule() public {
    bytes memory disableModuleData =
      abi.encodeWithSignature("disableModule(address,address)", SENTINELS, address(instance));

    _addSignersSameHat(2, signerHat);

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(disableModuleData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(IHatsSignerGate.CannotChangeModules.selector);

    // execute tx
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(disableGuardData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(IHatsSignerGate.CannotDisableThisGuard.selector);
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(changeThresholdData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(changeThresholdData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(addOwnerData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(removeOwnerData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(swapOwnerData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }

  function test_revert_delegatecallTargetNotEnabled() public {
    address target = makeAddr("target");

    _addSignersSameHat(2, signerHat);

    // craft a delegatecall to a non-enabled target
    bytes memory data = abi.encodeWithSignature("maliciousCall()");
    bytes32 txHash = _getTxHash(target, 0, Enum.Operation.DelegateCall, data, safe);
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    safe.execTransaction(
      target, 0, data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), signatures
    );
  }

  function test_revert_cannotCallSafe() public {
    _addSignersSameHat(3, signerHat);

    uint256 transferValue = 0.2 ether;

    // give the safe some eth
    hoax(address(safe), transferValue);

    // create the tx
    bytes32 txHash = _getTxHash(address(safe), transferValue, Enum.Operation.Call, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, 3);

    // try to exec the tx, expect it to revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    safe.execTransaction(
      address(safe),
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

  function test_revert_cannotChangeFallbackHandler() public {
    address newFallbackHandler = makeAddr("newFallbackHandler");

    _addSignersSameHat(3, signerHat);

    // data to change the fallback handler
    bytes memory changeFallbackHandlerData = abi.encodeWithSignature("setFallbackHandler(address)", newFallbackHandler);

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(changeFallbackHandlerData);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeFallbackHandler.selector));
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multisendCall,
      Enum.Operation.DelegateCall,
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

contract HSGGuarding is WithHSGInstanceTest {
  uint256 public disallowedValue = 1337;
  uint256 public goodValue = 9_000_000_000;
  address public recipient = makeAddr("recipient");
  uint256 public signerCount = 2;

  function setUp() public override {
    super.setUp();

    // set it on our hsg instance
    vm.prank(owner);
    instance.setGuard(address(tstGuard));
    assertEq(instance.getGuard(), address(tstGuard), "guard should be tstGuard");

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
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the `sender` param to be the Safe address because the sender param from hsg.checkTransaction is the
    // Safe address
    vm.expectEmit();
    emit TestGuard.PreChecked(address(safe));
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
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

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
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

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
