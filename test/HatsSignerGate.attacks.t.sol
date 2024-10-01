// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { WithHSGInstanceTest, Enum } from "./TestSuite.t.sol";
import { IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";

contract AttacksScenarios is WithHSGInstanceTest {
  function testSignersCannotAddNewModules() public {
    bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa));

    _addSignersSameHat(2, signerHat);

    bytes32 txHash = _getTxHash(address(safe), 0, addModuleData, safe);

    bytes memory signatures = _createNSigsForTx(txHash, 2);

    vm.expectRevert(IHatsSignerGate.SignersCannotChangeModules.selector);

    // execute tx
    safe.execTransaction(
      address(safe),
      0,
      addModuleData,
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

  function testTargetSigAttackFails() public {
    // set target threshold to 5
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(5);
    // initially there are 5 signers
    _addSignersSameHat(5, signerHat);

    // 3 owners lose their hats
    _setSignerValidity(signerAddresses[2], signerHat, false);
    _setSignerValidity(signerAddresses[3], signerHat, false);
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // reconcile is called, so signerCount is updated to 2
    hatsSignerGate.reconcileSignerCount();
    assertEq(hatsSignerGate.validSignerCount(), 2);
    assertEq(safe.getThreshold(), 2);

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
    bytes32 txHash = _getTxHash(destAddress, transferValue, hex"00", safe);
    // have them sign it
    bytes memory signatures = _createNSigsForTx(txHash, 2);

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
    assertEq(hatsSignerGate.targetThreshold(), 2, "target threshold");
    // start with 5 valid signers
    _addSignersSameHat(5, signerHat);

    // the last two lose their hats
    _setSignerValidity(signerAddresses[3], signerHat, false);
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // the 4th regains its hat
    _setSignerValidity(signerAddresses[3], signerHat, true);

    // remove the 5th signer
    hatsSignerGate.removeSigner(signerAddresses[4]);

    // signer count should be 4 and threshold at target
    assertEq(hatsSignerGate.validSignerCount(), 4, "valid signer count");
    assertEq(safe.getThreshold(), hatsSignerGate.targetThreshold(), "ending threshold");
  }

  function testCanClaimToReplaceInvalidSignerAtMaxSigner() public {
    // start with 5 valid signers (the max)
    _addSignersSameHat(5, signerHat);

    // the last one loses their hat
    _setSignerValidity(signerAddresses[4], signerHat, false);

    // a new signer valid tries to claim, and can
    _setSignerValidity(signerAddresses[5], signerHat, true);
    vm.prank(signerAddresses[5]);
    hatsSignerGate.claimSigner(signerHat);
    assertEq(hatsSignerGate.validSignerCount(), 5, "valid signer count");
  }

  function testSetTargetThresholdUpdatesThresholdCorrectly() public {
    // set target threshold to 5
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(5);
    // add 5 valid signers
    _addSignersSameHat(5, signerHat);
    // one loses their hat
    _setSignerValidity(signerAddresses[4], signerHat, false);
    // lower target threshold to 4
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(4);
    // since hatsSignerGate.validSignerCount() is also 4, the threshold should also be 4
    assertEq(safe.getThreshold(), 4, "threshold");
  }

  function testSetTargetTresholdCannotSetBelowMinThreshold() public {
    assertEq(hatsSignerGate.minThreshold(), 2, "min threshold");
    assertEq(hatsSignerGate.targetThreshold(), 2, "target threshold");

    // set target threshold to 1 — should fail
    vm.prank(owner);
    vm.expectRevert(IHatsSignerGate.InvalidTargetThreshold.selector);
    hatsSignerGate.setTargetThreshold(1);
  }

  function testAttackerCannotExploitSigHandlingDifferences() public {
    // start with 4 valid signers
    _addSignersSameHat(4, signerHat);
    // set target threshold (and therefore actual threshold) to 3
    vm.prank(owner);
    hatsSignerGate.setTargetThreshold(3);
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
      address(safe), // to
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
    bytes memory sigs = _createNSigsForTx(txHash, 3);

    // attacker adds a contract signature from the 4th signer from a previous tx
    // since HSG doesn't check that the correct data was signed, it would be considered a valid signature
    bytes memory contractSig = abi.encode(signerAddresses[3], bytes32(0), bytes1(0x01));
    sigs = bytes.concat(sigs, contractSig);

    // mock the maliciousTx so it would succeed if it were to be executed
    vm.mockCall(maliciousContract, maliciousTx, abi.encode(true));
    // attacker submits the tx to the safe, but it should fail
    vm.expectRevert(IHatsSignerGate.InvalidSigners.selector);
    vm.prank(attacker);
    safe.execTransaction(
      address(safe),
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
      sigs
    );

    assertEq(safe.getThreshold(), 3, "post threshold");
    assertEq(hatsSignerGate.validSignerCount(), 3, "valid signer count");
    assertEq(safe.nonce(), 0, "post nonce hasn't changed");
  }

  function testSignersCannotReenterCheckTransactionToAddOwners() public {
    address newOwner = makeAddr("newOwner");
    bytes memory addOwnerAction;
    bytes memory sigs;
    bytes memory checkTxAction;
    bytes memory multisend;
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
      sigs = _createNSigsForTx(dummyTxHash, 2);

      checkTxAction = abi.encodeWithSelector(
        hatsSignerGate.checkTransaction.selector,
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
        sigs,
        attacker // msgSender
      );

      // now bundle the two actions into a multisend tx
      bytes memory packedCalls = abi.encodePacked(
        // 1) add owner
        uint8(0), // 0 for call; 1 for delegatecall
        safe, // to
        uint256(0), // value
        uint256(addOwnerAction.length), // data length
        bytes(addOwnerAction), // data
        // 2) direct call to checkTransaction
        uint8(0), // 0 for call; 1 for delegatecall
        hatsSignerGate, // to
        uint256(0), // value
        uint256(checkTxAction.length), // data length
        bytes(checkTxAction) // data
      );
      multisend = abi.encodeWithSignature("multiSend(bytes)", packedCalls);
    }

    // now get the safe tx hash and have attacker sign it with a collaborator
    bytes32 safeTxHash = safe.getTransactionHash(
      safeMultisendLibrary, // to
      0, // value
      multisend, // data
      Enum.Operation.DelegateCall, // operation
      0, // safeTxGas
      0, // baseGas
      0, // gasPrice
      address(0), // gasToken
      address(0), // refundReceiver
      safe.nonce() // nonce
    );
    sigs = _createNSigsForTx(safeTxHash, 2);

    // now submit the tx to the safe
    vm.prank(attacker);
    /* 
        Expect revert because of re-entry into checkTransaction
        While hatsSignerGate will throw the NoReentryAllowed error, 
        since the error occurs within the context of the safe transaction, 
        the safe will catch the error and re-throw with its own error, 
        ie `GS013` ("Safe transaction failed when gasPrice and safeTxGas were 0")
        */
    vm.expectRevert(bytes("GS013"));
    safe.execTransaction(
      safeMultisendLibrary,
      0,
      multisend,
      Enum.Operation.DelegateCall,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      sigs
    );

    // no new owners have been added, despite the attacker's best efforts
    assertEq(safe.getOwners().length, 3, "post owner count");
  }
}
