// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { WithHSGInstanceTest, Enum } from "./TestSuite.t.sol";
import { IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { SafeManagerLib } from "../src/lib/SafeManagerLib.sol";

contract AttacksScenarios is WithHSGInstanceTest {
  address public maliciousFallbackHandler = makeAddr("maliciousFallbackHandler");
  address public goodFallbackHandler;
  bytes public setFallbackAction = abi.encodeWithSignature("setFallbackHandler(address)", maliciousFallbackHandler);
  bytes public packedCalls;
  bytes public multiSendData;
  bytes32 public safeTxHash;
  bytes public checkTransactionAction;
  bytes public signatures;

  bytes public checkAfterExecutionAction =
    abi.encodeWithSignature("checkAfterExecution(bytes32,bool)", bytes32(0), false);

  string public constant CHECK_TRANSACTION_SIGNATURE =
    "checkTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes,address)";

  function setUp() public override {
    super.setUp();

    goodFallbackHandler = SafeManagerLib.getSafeFallbackHandler(safe);
  }

  function testSignersCannotAddNewModules() public {
    _addSignersSameHat(2, signerHat);

    bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(tstModule1));

    (bytes memory multisendCall, bytes32 txHash) = _constructSingleActionMultiSendTx(addModuleData);

    signatures = _createNSigsForTx(txHash, 2);

    // execute tx, expecting a revert
    vm.expectRevert(IHatsSignerGate.CannotChangeModules.selector);
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

  function testTargetSigAttackFails() public {
    // set target threshold to 5
    IHatsSignerGate.ThresholdConfig memory newConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: 2,
      target: 5
    });
    vm.prank(owner);
    instance.setThresholdConfig(newConfig);
    // initially there are 5 signers
    _addSignersSameHat(5, signerHat);

    // 3 owners lose their hats
    _setSignerValidity(signerAddresses[2], signerHat, false);
    _setSignerValidity(signerAddresses[3], signerHat, false);
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // the 3 owners regain their hats
    _setSignerValidity(signerAddresses[2], signerHat, true);
    _setSignerValidity(signerAddresses[3], signerHat, true);
    _setSignerValidity(signerAddresses[4], signerHat, true);

    // set up test values
    // uint256 preNonce = safe.nonce();
    uint256 preValue = 1 ether;
    uint256 transferValue = 0.2 ether;
    // uint256 postValue = preValue - transferValue;
    address destAddress = signerAddresses[3];
    // give the safe some eth
    hoax(address(safe), preValue);

    // have just 2 of 5 signers sign it
    // create the tx
    bytes32 txHash = _getTxHash(destAddress, transferValue, Enum.Operation.Call, hex"00", safe);
    // have them sign it
    signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert();
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

  function testRemoveSignerCorrectlyUpdates() public {
    // sanity check that the min threshold is 2
    assertEq(instance.thresholdConfig().min, 2);

    // start with 5 valid signers
    _addSignersSameHat(5, signerHat);

    // the last two lose their hats
    _setSignerValidity(signerAddresses[3], signerHat, false);
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // the 4th regains its hat
    _setSignerValidity(signerAddresses[3], signerHat, true);

    // remove the 5th signer
    instance.removeSigner(signerAddresses[4]);

    // signer count should be 4 and threshold at target
    assertEq(instance.validSignerCount(), 4, "valid signer count");
    assertEq(safe.getThreshold(), instance.thresholdConfig().target, "ending threshold");
  }

  function testCanClaimToReplaceInvalidSignerAtMaxSigner() public {
    // start with 5 valid signers (the max)
    _addSignersSameHat(5, signerHat);

    // the last one loses their hat
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // a new signer valid tries to claim, and can
    _setSignerValidity(signerAddresses[5], signerHat, true);
    vm.prank(signerAddresses[5]);
    instance.claimSigner(signerHat);
    assertEq(instance.validSignerCount(), 5, "valid signer count");
  }

  function testSetTargetThresholdUpdatesThresholdCorrectly() public {
    // set target threshold to 5
    vm.prank(owner);
    instance.setThresholdConfig(
      IHatsSignerGate.ThresholdConfig({ thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE, min: 2, target: 5 })
    );
    // add 5 valid signers
    _addSignersSameHat(5, signerHat);
    // one loses their hat
    _setSignerValidity(signerAddresses[4], signerHat, false);
    // lower target threshold to 4
    vm.prank(owner);
    instance.setThresholdConfig(
      IHatsSignerGate.ThresholdConfig({ thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE, min: 2, target: 4 })
    );
    // since instance.validSignerCount() is also 4, the threshold should also be 4
    assertEq(safe.getThreshold(), 4, "threshold");
  }

  function testSetTargetThresholdCannotSetBelowMinThreshold() public {
    assertEq(instance.thresholdConfig().min, 2, "min threshold");
    assertEq(instance.thresholdConfig().target, 2, "target threshold");

    // set target threshold to 1 — should fail
    vm.prank(owner);
    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    instance.setThresholdConfig(
      IHatsSignerGate.ThresholdConfig({ thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE, min: 2, target: 1 })
    );
  }

  function testAttackerCannotExploitSigHandlingDifferences() public {
    // start with 4 valid signers
    _addSignersSameHat(4, signerHat);
    // set target threshold (and therefore actual threshold) to 3
    vm.prank(owner);
    instance.setThresholdConfig(
      IHatsSignerGate.ThresholdConfig({ thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE, min: 2, target: 3 })
    );
    assertEq(safe.getThreshold(), 3, "initial threshold");
    assertEq(safe.nonce(), 0, "pre nonce");
    // invalidate the 3rd signer, who will be our attacker
    address attacker = signerAddresses[2];
    _setSignerValidity(attacker, signerHat, false);

    // Attacker crafts a tx to submit to the safe.
    address maliciousContract = makeAddr("maliciousContract");
    bytes memory maliciousTx = abi.encodeWithSignature("maliciousCall(uint256)", 1 ether);
    // Attacker gets 2 of the valid signers to sign it, and adds their own (invalid) signature: NSigs = 3
    bytes32 txHash = safe.getTransactionHash(
      maliciousContract, // to
      0, // value
      maliciousTx, // data
      Enum.Operation.Call, // operation
      0, // safeTxGas
      0, // baseGas
      0, // gasPrice
      address(0), // gasToken
      address(0), // refundReceiver
      safe.nonce() // nonce
    );
    signatures = _createNSigsForTx(txHash, 3);

    // attacker adds a contract signature from the 4th signer from a previous tx
    // since HSG doesn't check that the correct data was signed, it would be considered a valid signature
    bytes memory contractSig = abi.encode(signerAddresses[3], bytes32(0), bytes1(0x01));
    signatures = bytes.concat(signatures, contractSig);

    // mock the maliciousTx so it would succeed if it were to be executed
    vm.mockCall(maliciousContract, maliciousTx, abi.encode(true));
    // attacker submits the tx to the safe, but it should fail
    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);
    vm.prank(attacker);
    safe.execTransaction(
      maliciousContract,
      0,
      maliciousTx,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      // (r,s,v) [r - from] [s - unused] [v - 1 flag for onchain approval]
      signatures
    );

    assertEq(safe.getThreshold(), 3, "post threshold");
    assertEq(instance.validSignerCount(), 3, "valid signer count");
    assertEq(safe.nonce(), 0, "post nonce hasn't changed");
  }

  function test_revert_reenterCheckTransaction() public {
    address newOwner = makeAddr("newOwner");
    bytes memory addOwnerAction;
    bytes memory checkTxAction;
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);
    // attacker is the first of these signers
    address attacker = signerAddresses[0];
    assertEq(safe.getThreshold(), 2, "initial threshold");
    assertEq(safe.getOwners().length, 3, "initial owner count");

    /* attacker crafts a multisend tx to submit to the safe, with the following actions:
            1) add a new owner 
                — when `HSG.checkTransaction` is called, the hash of the original owner array will be stored
            2) directly call `HSG.checkTransaction` 
                — this will cause the hash of the new owner array (with the new owner from #1) to be stored
                — when `HSG.checkAfterExecution` is called, the owner array check will pass even though 
        */

    // 1) craft the addOwner action
    // mock the new owner as a valid signer
    _setSignerValidity(newOwner, signerHat, true);
    {
      // use scope to avoid stack too deep error
      // compile the action
      addOwnerAction = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", newOwner, 2);

      // 2) craft the direct checkTransaction action
      // first craft a dummy/empty tx to pass to checkTransaction
      bytes32 dummyTxHash = safe.getTransactionHash(
        attacker, // send 0 eth to the attacker
        0,
        hex"00",
        Enum.Operation.Call,
        // not using the refunder
        0,
        0,
        0,
        address(0),
        address(0),
        safe.nonce()
      );

      // then have it signed by the attacker and a collaborator
      // sigs =

      checkTxAction = abi.encodeWithSelector(
        instance.checkTransaction.selector,
        // checkTransaction params
        attacker,
        0,
        hex"00",
        Enum.Operation.Call,
        0,
        0,
        0,
        address(0),
        payable(address(0)),
        _createNSigsForTx(dummyTxHash, 2),
        attacker // msgSender
      );

      // now bundle the two actions into a multisend tx
      packedCalls = abi.encodePacked(
        // 1) add owner
        uint8(0), // 0 for call; 1 for delegatecall
        safe, // to
        uint256(0), // value
        uint256(addOwnerAction.length), // data length
        bytes(addOwnerAction), // data
        // 2) direct call to checkTransaction
        uint8(0), // 0 for call; 1 for delegatecall
        instance, // to
        uint256(0), // value
        uint256(checkTxAction.length), // data length
        bytes(checkTxAction) // data
      );
      multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);
    }

    // now get the safe tx hash and have attacker sign it with a collaborator
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0, // value
      multiSendData, // data
      Enum.Operation.DelegateCall, // operation
      0, // safeTxGas
      0, // baseGas
      0, // gasPrice
      address(0), // gasToken
      address(0), // refundReceiver
      safe.nonce() // nonce
    );
    signatures = _createNSigsForTx(safeTxHash, 2);

    // now submit the tx to the safe
    vm.prank(attacker);
    /* 
        Expect revert because of re-entry into checkTransaction
        While instance will throw the NoReentryAllowed error, 
        since the error occurs within the context of the safe transaction, 
        the safe will catch the error and re-throw with its own error, 
        ie `GS013` ("Safe transaction failed when gasPrice and safeTxGas were 0")
        */
    vm.expectRevert(bytes("GS013"));
    safe.execTransaction(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // no new owners have been added, despite the attacker's best efforts
    assertEq(safe.getOwners().length, 3, "post owner count");
  }

  function test_revert_callCheckTransactionFromMultisend() public {
    // our scenario starts with HSG attached to a safe, with 3 valid signers and a threshold of 2
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains two actions:
    // 1) set the maliciousFallback as the fallback
    // 2) calls Safe.execTransaction with valid signatures. This can be an empty tx; its just there to enter the
    // guard functions to overwrite the snapshot so the outer call can pass the checks.

    // 1) set the maliciousFallbackHandler as the fallback
    // bytes memory setFallbackAction = abi.encodeWithSignature("setFallbackHandler(address)",
    // maliciousFallbackHandler);

    // 2) call Safe.execTransaction with valid signatures
    // get the hash of the empty action
    bytes32 emptyTransactionHash = safe.getTransactionHash(
      address(signerAddresses[0]), // must be non-safe target
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce() + 1 // nonce increments after the outer call to execTransaction
    );
    // sufficient signers sign it
    // bytes memory emptySigs = _createNSigsForTx(emptyTransactionHash, 2);

    // get the calldata
    bytes memory emptyExecTransactionAction = abi.encodeWithSignature(
      "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
      address(signerAddresses[0]), // must be non-safe target
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      _createNSigsForTx(emptyTransactionHash, 2)
    );

    // bundle the two actions into a multisend
    packedCalls = abi.encodePacked(
      // 1) setFallback
      uint8(0), // 0 for call; 1 for delegatecall
      safe, // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction), // data
      // 2) execTransaction
      uint8(0), // 0 for call; 1 for delegatecall
      safe, // to
      uint256(0), // value
      uint256(emptyExecTransactionAction.length), // data length
      bytes(emptyExecTransactionAction) // INNER action
    );

    // OUTER action
    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash and have the signers sign it
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    signatures = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    vm.prank(signerAddresses[0]);
    /* 
      Expect revert because of re-entry into checkTransaction
      While instance will throw the NoReentryAllowed error, 
      since the error occurs within the context of the safe transaction, 
      the safe will catch the error and re-throw with its own error, 
      ie `GS013` ("Safe transaction failed when gasPrice and safeTxGas were 0")
      */
    vm.expectRevert("GS013");
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should not be different
    address fallbackHandler = SafeManagerLib.getSafeFallbackHandler(safe);
    assertEq(fallbackHandler, goodFallbackHandler, "fallbackHandler should be the same as before");
  }

  function test_revert_callCheckAfterExecutionInsideMultisend() public {
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains three actions:
    // 1) set the maliciousFallbackHandler as the fallback — this will set the _inExecTransaction flag to true
    // 2) HSG.checkAfterExecution — this will reset the _inExecTransaction flag to false
    // 3) HSG.checkTransaction — this will set the _inExecTransaction flag to back to true and overwrite the snapshot

    // 1) set the maliciousFallbackHandler as the fallback
    // bytes memory setFallbackAction = abi.encodeWithSignature("setFallbackHandler(address)",
    // maliciousFallbackHandler);

    // 2) HSG.checkAfterExecution
    // bytes memory checkAfterExecutionAction =
    //   abi.encodeWithSignature("checkAfterExecution(bytes32,bool)", bytes32(0), false);

    // 3) HSG.checkTransaction
    {
      checkTransactionAction = abi.encodeWithSignature(
        CHECK_TRANSACTION_SIGNATURE,
        address(0),
        0,
        hex"",
        Enum.Operation.Call,
        0,
        0,
        0,
        address(0),
        address(0),
        _createNContractSigs(2), // attacker's spoofed signatures
        address(safe)
      );

      // bundle the three actions into a multisend
      packedCalls = abi.encodePacked(
        // 1) setFallback
        uint8(0), // 0 for call; 1 for delegatecall
        address(safe), // to
        uint256(0), // value
        uint256(setFallbackAction.length), // data length
        bytes(setFallbackAction), // data
        // 2) checkAfterExecution
        uint8(0), // 0 for call; 1 for delegatecall
        address(instance), // to
        uint256(0), // value
        uint256(checkAfterExecutionAction.length), // data length
        bytes(checkAfterExecutionAction) // data
      );

      // workaround to avoid stack too deep error
      packedCalls = abi.encodePacked(
        packedCalls,
        // 3) checkTransaction
        uint8(0), // 0 for call; 1 for delegatecall
        address(instance), // to
        uint256(0), // value
        uint256(checkTransactionAction.length), // data length
        bytes(checkTransactionAction) // data
      );

      multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

      safeTxHash = _getSafeDelegatecallHash(defaultDelegatecallTargets[0], multiSendData, safe);

      signatures = _createNSigsForTx(safeTxHash, 2);
    }

    // submit the tx to the safe, expecting a revert
    vm.expectRevert("GS013");
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should not be different
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same as before"
    );
  }

  function test_revert_callCheckAfterExecutionFromMultisend() public {
    // our scenario starts with HSG attached to a safe, with 3 valid signers and a threshold of 2
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains two actions:
    // 1) HSG.checkAfterExecution — this will reset the _inSafeExecTransaction flag to false after it was set to
    // true in checkTransaction
    // 2) set the maliciousFallbackHandler as the fallback
    // 3) Safe.execTransaction

    // 1) HSG.checkAfterExecution
    // bytes memory checkAfterExecutionAction =
    // abi.encodeWithSignature("checkAfterExecution(bytes32,bool)", bytes32(0), false);

    // 2) set the maliciousFallbackHandler as the fallback
    // bytes memory setFallbackAction = abi.encodeWithSignature("setFallbackHandler(address)",
    // maliciousFallbackHandler);

    // 3) call Safe.execTransaction with valid signatures
    // get the hash of the empty action
    bytes32 emptyTransactionHash = safe.getTransactionHash(
      address(signerAddresses[0]), // must be non-safe target
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce() + 1 // nonce increments after the outer call to execTransaction
    );
    // sufficient signers sign it
    bytes memory emptySigs = _createNSigsForTx(emptyTransactionHash, 2);

    // get the calldata
    bytes memory emptyExecTransactionAction = abi.encodeWithSignature(
      "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
      address(signerAddresses[0]), // must be non-safe target
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      emptySigs
    );

    // bundle the three actions into a multisend
    packedCalls = abi.encodePacked(
      // checkTransaction
      // 1) checkAfterExecution
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkAfterExecutionAction.length), // data length
      bytes(checkAfterExecutionAction), // data
      // 2) setFallback
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction) // data
    );

    // workaround to avoid stack too deep error
    packedCalls = abi.encodePacked(
      packedCalls,
      // 3) execTransaction
      // checkTransaction
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(emptyExecTransactionAction.length), // data length
      bytes(emptyExecTransactionAction) // data
        // checkAfterExecution
        // checkAfterExecution
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash and have the signers sign it
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    signatures = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    vm.prank(signerAddresses[0]);
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should be different
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same asbefore"
    );
  }

  function test_revert_bypassHSGGuardByDisablingHSG() public {
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains three actions:
    // 1) HSG.checkAfterExecution — this will reset the _inSafeExecTransaction flag to false after it was set to
    // true in the outer call
    // 2) Safe.setFallbackHandler to set the maliciousFallbackHandler as the fallback
    // 3) HSG.checkTransaction — this will set the _inSafeExecTransaction flag to back to true and overwrite the
    // snapshot

    // 1) HSG.checkAfterExecution
    // bytes memory checkAfterExecutionAction =
    //   abi.encodeWithSignature("checkAfterExecution(bytes32,bool)", bytes32(0), false);

    // 2) Safe.setFallbackHandler to set the maliciousFallbackHandler as the fallback
    //   bytes memory setFallbackAction = abi.encodeWithSignature("setFallbackHandler(address)",
    // maliciousFallbackHandler);

    // 3) HSG.checkTransaction
    checkTransactionAction = abi.encodeWithSignature(
      CHECK_TRANSACTION_SIGNATURE,
      address(0),
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      _createNContractSigs(2), // attacker's spoofed signatures
      address(safe)
    );

    // bundle the three actions into a multisend
    packedCalls = abi.encodePacked(
      // 1) checkAfterExecution
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkAfterExecutionAction.length), // data length
      bytes(checkAfterExecutionAction), // data
      // 2) setFallback
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction) // data
    );

    // workaround to avoid stack too deep error
    packedCalls = abi.encodePacked(
      packedCalls,
      // 3) checkTransaction
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkTransactionAction.length), // data length
      bytes(checkTransactionAction) // data
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash and have the signers sign it
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    // signers sign the tx
    bytes memory sigs = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    vm.prank(signerAddresses[0]);
    vm.expectRevert("GS013");
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      sigs
    );

    // the fallback should be different
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same as before"
    );
  }

  function test_revert_callExecTransactionFromModuleInsideMultisend() public {
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains four actions:
    // 1) HSG.checkAfterExecution — this will reset the _inSafeExecTransaction flag to false after it was set to
    // true in checkTransaction
    // 2) Safe.setFallbackHandler to set the maliciousFallbackHandler as the fallback
    // 3) HSG.execTransactionFromModule — this will update the Safe state snapshot
    // But the outer call to HSG.checkAfterExecution will revert because the _inSafeExecTransaction flag is false

    // simplest version of (3) requires that the safe has somehow been enabled as a module on HSG. Otherwise, it will
    // revert with a NotAuthorized() error.
    vm.prank(owner);
    instance.enableModule(address(safe));

    // (3) craft an empty execTransactionFromModule call
    bytes memory execTransactionFromModuleAction = abi.encodeWithSignature(
      "execTransactionFromModule(address,uint256,bytes,uint8)", address(0), 0, hex"", Enum.Operation.Call
    );

    // 4) HSG.checkTransaction
    checkTransactionAction = abi.encodeWithSignature(
      CHECK_TRANSACTION_SIGNATURE,
      address(0),
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      _createNContractSigs(2), // attacker's spoofed signatures
      address(safe)
    );

    // bundle the three actions into a multisend
    packedCalls = abi.encodePacked(
      // 1) checkAfterExecution
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkAfterExecutionAction.length), // data length
      bytes(checkAfterExecutionAction), // data
      // 2) setFallback
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction) // data
    );

    // workaround to avoid stack too deep error
    packedCalls = abi.encodePacked(
      packedCalls,
      // 3) execTransactionFromModule
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(execTransactionFromModuleAction.length), // data length
      bytes(execTransactionFromModuleAction) // data
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    // signers sign the tx
    signatures = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    vm.prank(signerAddresses[0]);
    // since the revert comes from the outer call to HSG.checkAfterExecution, we expect NoReentryAllowed because the
    // call to checkAfterExecution comes after the error catching in Safe.execTransaction
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should the same
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same as before"
    );
  }

  function test_revert_callExecTransactionFromModuleInsideMultisendWithCheckTransaction() public {
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains four actions:
    // 1) HSG.checkAfterExecution — this will reset the _inSafeExecTransaction flag to false after it was set to
    // true in checkTransaction
    // 2) Safe.setFallbackHandler to set the maliciousFallbackHandler as the fallback
    // 3) HSG.execTransactionFromModule — this will update the Safe state snapshot
    // 4) HSG.checkTransaction — this will set the _inSafeExecTransaction flag to true. But this should revert
    // because the nonce checks prevent checkTransaction from being called more than once

    // simplest version of (3) requires that the safe has somehow been enabled as a module on HSG. Otherwise, it will
    // revert with a NotAuthorized() error.
    vm.prank(owner);
    instance.enableModule(address(safe));

    // (3) craft an empty execTransactionFromModule call
    bytes memory execTransactionFromModuleAction = abi.encodeWithSignature(
      "execTransactionFromModule(address,uint256,bytes,uint8)", address(0), 0, hex"", Enum.Operation.Call
    );

    // 4) HSG.checkTransaction
    checkTransactionAction = abi.encodeWithSignature(
      CHECK_TRANSACTION_SIGNATURE,
      address(0),
      0,
      hex"",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      _createNContractSigs(2), // attacker's spoofed signatures
      address(safe)
    );

    // bundle the three actions into a multisend
    packedCalls = abi.encodePacked(
      // 1) checkAfterExecution
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkAfterExecutionAction.length), // data length
      bytes(checkAfterExecutionAction), // data
      // 2) setFallback
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction) // data
    );

    // workaround to avoid stack too deep error
    packedCalls = abi.encodePacked(
      packedCalls,
      // 3) execTransactionFromModule
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(execTransactionFromModuleAction.length), // data length
      bytes(execTransactionFromModuleAction), // data
      // 4) checkTransaction
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkTransactionAction.length), // data length
      bytes(checkTransactionAction) // data
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    // signers sign the tx
    signatures = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    vm.prank(signerAddresses[0]);
    // We expect GS013 since Safe.execTransaction catches the error NoReentryAllowed error thrown by
    // HSG.checkTransaction
    vm.expectRevert("GS013");
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should the same
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same as before"
    );
  }

  function test_revert_changeFallbackHandlerViaExecTransactionFromModuleInsideMultisend() public {
    // start with 3 valid signers
    _addSignersSameHat(3, signerHat);

    // the attacker crafts a multisend tx that contains two actions:
    // 1) HSG.checkAfterExecution — this will reset the _inSafeExecTransaction flag to false after it was set to
    // true in checkTransaction
    // 2) HSG.execTransactionFromModule with a payload that changes the fallback handler inside of a multisend. This
    // should revert because changing safe state is not allowed.

    // simplest version of (2) requires that the safe has somehow been enabled as a module on HSG. Otherwise, it will
    // revert with a NotAuthorized() error.
    vm.prank(owner);
    instance.enableModule(address(safe));

    // (2) craft the execTransactionFromModule action
    packedCalls = abi.encodePacked(
      uint8(0), // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(setFallbackAction.length), // data length
      bytes(setFallbackAction) // data
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    bytes memory execTransactionFromModuleAction = abi.encodeWithSignature(
      "execTransactionFromModule(address,uint256,bytes,uint8)",
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall
    );

    // bundle the two actions into a multisend
    packedCalls = abi.encodePacked(
      // 1) checkAfterExecution
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(checkAfterExecutionAction.length), // data length
      bytes(checkAfterExecutionAction), // data
      // 2) execTransactionFromModule
      uint8(0), // 0 for call; 1 for delegatecall
      address(instance), // to
      uint256(0), // value
      uint256(execTransactionFromModuleAction.length), // data length
      bytes(execTransactionFromModuleAction) // data
    );

    multiSendData = abi.encodeWithSignature("multiSend(bytes)", packedCalls);

    // get the safe tx hash
    safeTxHash = safe.getTransactionHash(
      defaultDelegatecallTargets[0], // to an approved delegatecall target
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    // signers sign the tx
    signatures = _createNSigsForTx(safeTxHash, 2);

    // submit the tx to the safe, expecting a revert
    // We expect GS013 since Safe.execTransaction catches the CannotChangeFallbackHandler error thrown by
    // HSG.execTransactionFromModule
    vm.expectRevert("GS013");
    safe.execTransaction(
      defaultDelegatecallTargets[0],
      0,
      multiSendData,
      Enum.Operation.DelegateCall,
      // not using the refunders
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // the fallback should the same
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe), goodFallbackHandler, "fallbackHandler should be the same as before"
    );
  }
}
