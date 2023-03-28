// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGTestSetup.t.sol";

contract HatsSignerGateTest is HSGTestSetup {
    function testSetTargetThreshold() public {
        addSigners(1);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(3);
        hatsSignerGate.setTargetThreshold(3);

        assertEq(hatsSignerGate.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 1);
    }

    function testSetTargetThreshold3of4() public {
        addSigners(4);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(3);

        hatsSignerGate.setTargetThreshold(3);

        assertEq(hatsSignerGate.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 3);
    }

    function testSetTargetThreshold4of4() public {
        addSigners(4);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(4);

        hatsSignerGate.setTargetThreshold(4);

        assertEq(hatsSignerGate.targetThreshold(), 4);
        assertEq(safe.getThreshold(), 4);
    }

    function testNonOwnerHatWearerCannotSetTargetThreshold() public {
        mockIsWearerCall(address(this), ownerHat, false);

        vm.expectRevert("UNAUTHORIZED");

        hatsSignerGate.setTargetThreshold(3);

        assertEq(hatsSignerGate.targetThreshold(), 2);
        assertEq(safe.getThreshold(), 1);
    }

    function testSetMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);
        hatsSignerGate.setTargetThreshold(3);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.MinThresholdSet(3);

        hatsSignerGate.setMinThreshold(3);

        assertEq(hatsSignerGate.minThreshold(), 3);
    }

    function testSetInvalidMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectRevert(InvalidMinThreshold.selector);
        hatsSignerGate.setMinThreshold(3);
    }

    function testNonOwnerCannotSetMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, false);

        vm.expectRevert("UNAUTHORIZED");

        hatsSignerGate.setMinThreshold(1);

        assertEq(hatsSignerGate.minThreshold(), 2);
    }

    function testReconcileSignerCount() public {
        mockIsWearerCall(addresses[1], signerHat, false);
        mockIsWearerCall(addresses[2], signerHat, false);
        mockIsWearerCall(addresses[3], signerHat, false);
        // add 3 more safe owners the old fashioned way
        // 1
        bytes memory addOwnersData1 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[1], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hatsSignerGate));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData1, // data
            Enum.Operation.Call // operation
        );

        // 2
        bytes memory addOwnersData2 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[2], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hatsSignerGate));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData2, // data
            Enum.Operation.Call // operation
        );

        // 3
        bytes memory addOwnersData3 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[3], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hatsSignerGate));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData3, // data
            Enum.Operation.Call // operation
        );

        assertEq(hatsSignerGate.validSignerCount(), 0);

        // set only two of them as valid signers
        mockIsWearerCall(address(hatsSignerGate), signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        // do the reconcile
        hatsSignerGate.reconcileSignerCount();

        assertEq(hatsSignerGate.validSignerCount(), 2);
        assertEq(safe.getThreshold(), 2);

        // now we can remove both the invalid signers with no changes to hatsSignerCount
        mockIsWearerCall(addresses[2], signerHat, false);
        hatsSignerGate.removeSigner(addresses[2]);
        mockIsWearerCall(addresses[3], signerHat, false);
        hatsSignerGate.removeSigner(addresses[3]);

        assertEq(hatsSignerGate.validSignerCount(), 2);
        assertEq(safe.getThreshold(), 2);
    }

    function testAddSingleSigner() public {
        addSigners(1);

        assertEq(safe.getOwners().length, 1);

        assertEq(hatsSignerGate.validSignerCount(), 1);

        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 1);
    }

    function testAddThreeSigners() public {
        addSigners(3);

        assertEq(hatsSignerGate.validSignerCount(), 3);

        assertEq(safe.getOwners()[0], addresses[2]);
        assertEq(safe.getOwners()[1], addresses[1]);
        assertEq(safe.getOwners()[2], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testAddTooManySigners() public {
        addSigners(5);

        mockIsWearerCall(addresses[5], signerHat, true);

        vm.expectRevert(MaxSignersReached.selector);
        vm.prank(addresses[5]);

        // this call should fail
        hatsSignerGate.claimSigner();

        assertEq(hatsSignerGate.validSignerCount(), 5);

        assertEq(safe.getOwners()[0], addresses[4]);
        assertEq(safe.getOwners()[1], addresses[3]);
        assertEq(safe.getOwners()[2], addresses[2]);
        assertEq(safe.getOwners()[3], addresses[1]);
        assertEq(safe.getOwners()[4], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, true);

        vm.prank(addresses[3]);
        hatsSignerGate.claimSigner();

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners().length, 1);
    }

    function testOwnerClaimSignerReverts() public {
        addSigners(2);

        vm.prank(addresses[1]);

        vm.expectRevert(abi.encodeWithSelector(SignerAlreadyClaimed.selector, addresses[1]));

        hatsSignerGate.claimSigner();

        assertEq(hatsSignerGate.validSignerCount(), 2);
    }

    function testNonHatWearerCannotClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, false);

        vm.prank(addresses[3]);

        vm.expectRevert(abi.encodeWithSelector(NotSignerHatWearer.selector, addresses[3]));
        hatsSignerGate.claimSigner();
    }

    function testCanRemoveInvalidSigner1() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, false);

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], address(hatsSignerGate));
        assertEq(hatsSignerGate.validSignerCount(), 0);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerWhenMultipleSigners() public {
        addSigners(2);

        mockIsWearerCall(addresses[0], signerHat, false);

        // emit log_uint(hatsSignerGate.signerCount());

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[1]);
        assertEq(hatsSignerGate.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerAfterReconcile2Signers() public {
        addSigners(2);

        mockIsWearerCall(addresses[0], signerHat, false);

        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 1);

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[1]);
        assertEq(hatsSignerGate.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerAfterReconcile3PLusSigners() public {
        addSigners(3);

        mockIsWearerCall(addresses[0], signerHat, false);

        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 2);

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getOwners()[0], addresses[2]);
        assertEq(safe.getOwners()[1], addresses[1]);
        assertEq(hatsSignerGate.validSignerCount(), 2);

        assertEq(safe.getThreshold(), 2);
    }

    function testCannotRemoveValidSigner() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(StillWearsSignerHat.selector, addresses[0]));

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[0]);
        assertEq(hatsSignerGate.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function testExecTxByHatWearers() public {
        addSigners(3);

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3);

        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);
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
        addSigners(3);

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        // uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);
        // emit log_uint(address(safe).balance);
        // create tx to send some eth from safe to wherever
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3);

        // removing the hats from 2 signers
        mockIsWearerCall(addresses[0], signerHat, false);
        mockIsWearerCall(addresses[1], signerHat, false);

        // emit log_uint(address(safe).balance);
        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);

        // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
        vm.expectRevert(InvalidSigners.selector);

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
        addSigners(1);

        // set up test values
        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        // uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // have the remaining signer sign it
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have them sign it
        bytes memory signatures = createNSigsForTx(txHash, 1);

        // have the legit signer exec the tx
        vm.prank(addresses[0]);

        mockIsWearerCall(addresses[0], signerHat, true);

        vm.expectRevert(
            abi.encodeWithSelector(BelowMinThreshold.selector, hatsSignerGate.minThreshold(), safe.getOwners().length)
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
        emit log_uint(address(safe).balance);
    }

    function testExecByLessThanMinThresholdReverts() public {
        addSigners(2);

        mockIsWearerCall(addresses[1], signerHat, false);
        assertEq(safe.getThreshold(), 2);

        // set up test values
        // uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        // uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // have the remaining signer sign it
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);
        // have them sign it
        bytes memory signatures = createNSigsForTx(txHash, 1);

        hatsSignerGate.reconcileSignerCount();
        assertEq(safe.getThreshold(), 1);

        // vm.expectRevert(abi.encodeWithSelector(BelowMinThreshold.selector, minThreshold, 1));
        vm.expectRevert(InvalidSigners.selector);
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

    function testCannotDisableModule() public {
        bytes memory disableModuleData =
            abi.encodeWithSignature("disableModule(address,address)", SENTINELS, address(hatsSignerGate));

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(SignersCannotChangeModules.selector);

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

        // executeSafeTxFrom(address(this), disableModuleData, safe);
    }

    function testCannotDisableGuard() public {
        bytes memory disableGuardData = abi.encodeWithSignature("setGuard(address)", address(0x0));

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableGuardData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(CannotDisableThisGuard.selector, address(hatsSignerGate)));
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
        addSigners(3);

        uint256 oldThreshold = safe.getThreshold();
        assertEq(oldThreshold, 2);

        // data to increase the threshold data by 1
        bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold + 1);

        bytes32 txHash = getTxHash(address(safe), 0, changeThresholdData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(SignersCannotChangeThreshold.selector));
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
        addSigners(3);

        uint256 oldThreshold = safe.getThreshold();
        assertEq(oldThreshold, 2);

        // data to decrease the threshold data by 1
        bytes memory changeThresholdData = abi.encodeWithSignature("changeThreshold(uint256)", oldThreshold - 1);

        bytes32 txHash = getTxHash(address(safe), 0, changeThresholdData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(SignersCannotChangeThreshold.selector));
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
        addSigners(3);
        // data for call to add owners
        bytes memory addOwnerData = abi.encodeWithSignature(
            "addOwnerWithThreshold(address,uint256)",
            addresses[9], // newOwner
            safe.getThreshold() // threshold
        );

        bytes32 txHash = getTxHash(address(safe), 0, addOwnerData, safe);
        bytes memory signatures = createNSigsForTx(txHash, 2);

        // ensure 2 signers are valid
        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);
        // mock call to attempted new owner (doesn't matter if valid or not)
        mockIsWearerCall(addresses[9], signerHat, false);

        vm.expectRevert(abi.encodeWithSelector(SignersCannotChangeOwners.selector));
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
        addSigners(3);
        address toRemove = addresses[2];
        // data for call to remove owners
        bytes memory removeOwnerData = abi.encodeWithSignature(
            "removeOwner(address,address,uint256)",
            findPrevOwner(safe.getOwners(), toRemove), // prevOwner
            toRemove, // owner to remove
            safe.getThreshold() // threshold
        );

        bytes32 txHash = getTxHash(address(safe), 0, removeOwnerData, safe);
        bytes memory signatures = createNSigsForTx(txHash, 2);

        // ensure 2 signers are valid
        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(SignersCannotChangeOwners.selector));
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
        addSigners(3);
        address toRemove = addresses[2];
        address toAdd = addresses[9];
        // data for call to swap owners
        bytes memory swapOwnerData = abi.encodeWithSignature(
            "swapOwner(address,address,address)",
            findPrevOwner(safe.getOwners(), toRemove), // prevOwner
            toRemove, // owner to swap
            toAdd // newOwner
        );

        bytes32 txHash = getTxHash(address(safe), 0, swapOwnerData, safe);
        bytes memory signatures = createNSigsForTx(txHash, 2);

        // ensure 2 signers are valid
        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);
        // mock call to attempted new owner (doesn't matter if valid or not)
        mockIsWearerCall(toAdd, signerHat, false);

        vm.expectRevert(abi.encodeWithSelector(SignersCannotChangeOwners.selector));
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

    function testCannotCallCheckTransactionFromNonSafe() public {
        vm.expectRevert(NotCalledFromSafe.selector);
        hatsSignerGate.checkTransaction(
            address(0), 0, hex"00", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"00", address(0)
        );
    }

    function testCannotCallCheckAfterExecutionFromNonSafe() public {
        vm.expectRevert(NotCalledFromSafe.selector);
        hatsSignerGate.checkAfterExecution(hex"00", true);
    }

    function testAttackOnMaxSignerFails() public {
        // max signers is 5
        // 5 signers claim
        addSigners(5);

        // a signer misbehaves and loses the hat
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 4
        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 4);

        // a new signer claims, so signerCount is updated to 5
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hatsSignerGate.claimSigner();
        assertEq(hatsSignerGate.validSignerCount(), 5);

        // the malicious signer behaves nicely and regains the hat, but they were kicked out by the previous signer claim
        mockIsWearerCall(addresses[4], signerHat, true);

        // reoncile is called again and signerCount stays at 5
        // vm.expectRevert(MaxSignersReached.selector);
        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 5);

        // // any eligible signer can now claim at will
        // mockIsWearerCall(addresses[6], signerHat, true);
        // vm.prank(addresses[6]);
        // hatsSignerGate.claimSigner();
        // assertEq(hatsSignerGate.signerCount(), 7);
    }

    function testAttackOnMaxSigner2Fails() public {
        // max signers is x
        // 1) we grant x signers
        addSigners(5);
        // 2) 3 signers lose validity
        mockIsWearerCall(addresses[2], signerHat, false);
        mockIsWearerCall(addresses[3], signerHat, false);
        mockIsWearerCall(addresses[4], signerHat, false);

        // 3) reconcile is called, signerCount=x-3
        hatsSignerGate.reconcileSignerCount();
        console2.log("A");
        assertEq(hatsSignerGate.validSignerCount(), 2);

        // 4) 3 more signers can be added with claimSigner()
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hatsSignerGate.claimSigner();
        mockIsWearerCall(addresses[6], signerHat, true);
        vm.prank(addresses[6]);
        hatsSignerGate.claimSigner();
        mockIsWearerCall(addresses[7], signerHat, true);
        vm.prank(addresses[7]);
        hatsSignerGate.claimSigner();

        console2.log("B");
        assertEq(hatsSignerGate.validSignerCount(), 5);
        console2.log("C");
        assertEq(safe.getOwners().length, 5);

        // 5) the 3 signers from (2) regain their validity
        mockIsWearerCall(addresses[2], signerHat, true);
        mockIsWearerCall(addresses[3], signerHat, true);
        mockIsWearerCall(addresses[4], signerHat, true);

        // but we still only have 5 owners and 5 signers
        console2.log("D");
        assertEq(hatsSignerGate.validSignerCount(), 5);

        console2.log("E");
        assertEq(safe.getOwners().length, 5);

        console2.log("F");
        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 5);

        // // 6) we now have x+3 signers
        // hatsSignerGate.reconcileSignerCount();
        // assertEq(hatsSignerGate.signerCount(), 8);
    }

    function testValidSignersCanClaimAfterMaxSignerLosesHat() public {
        // max signers is 5
        // 5 signers claim
        addSigners(5);

        // a signer misbehaves and loses the hat
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 4
        hatsSignerGate.reconcileSignerCount();

        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hatsSignerGate.claimSigner();
    }

    function testSignersCannotAddNewModules() public {
        bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, addModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(SignersCannotChangeModules.selector);

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

    function testOwnerCanAddNewModule() public {
        mockIsWearerCall(address(this), ownerHat, true);
        hatsSignerGate.enableNewModule(address(0xf00baa));

        assertEq(hatsSignerGate.enabledModuleCount(), 2);
    }

    function testSignersCannotAddNewModulesWithExistingEnabledModule() public {
        mockIsWearerCall(address(this), ownerHat, true);
        hatsSignerGate.enableNewModule(address(0xdec1a551f1ed));

        assertEq(hatsSignerGate.enabledModuleCount(), 2);

        bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, addModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(SignersCannotChangeModules.selector);

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
        mockIsWearerCall(address(this), ownerHat, true);
        hatsSignerGate.setTargetThreshold(5);
        // initially there are 5 signers
        addSigners(5);

        // 3 owners lose their hats
        mockIsWearerCall(addresses[2], signerHat, false);
        mockIsWearerCall(addresses[3], signerHat, false);
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 2
        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 2);
        assertEq(safe.getThreshold(), 2);

        // the 3 owners regain their hats
        mockIsWearerCall(addresses[2], signerHat, true);
        mockIsWearerCall(addresses[3], signerHat, true);
        mockIsWearerCall(addresses[4], signerHat, true);

        // set up test values
        // uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        // uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // have just 2 of 5 signers sign it
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);
        // have them sign it
        bytes memory signatures = createNSigsForTx(txHash, 2);

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

    function testCannotClaimSignerIfNoInvalidSigners() public {
        assertEq(maxSigners, 5);
        addSigners(5);
        // one signer loses their hat
        mockIsWearerCall(addresses[4], signerHat, false);
        assertEq(hatsSignerGate.validSignerCount(), 4);

        // reconcile is called, updating signer count to 4
        hatsSignerGate.reconcileSignerCount();
        assertEq(hatsSignerGate.validSignerCount(), 4);

        // bad signer regains their hat
        mockIsWearerCall(addresses[4], signerHat, true);
        // signer count returns to 5
        assertEq(hatsSignerGate.validSignerCount(), 5);

        // new valid signer tries to claim, but can't because we're already at max signers
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        vm.expectRevert(MaxSignersReached.selector);
        hatsSignerGate.claimSigner();
    }

    function testRemoveSignerCorrectlyUpdates() public {
        assertEq(hatsSignerGate.targetThreshold(), 2, "target threshold");
        assertEq(maxSigners, 5, "max signers");
        // start with 5 valid signers
        addSigners(5);

        // the last two lose their hats
        mockIsWearerCall(addresses[3], signerHat, false);
        mockIsWearerCall(addresses[4], signerHat, false);

        // the 4th regains its hat
        mockIsWearerCall(addresses[3], signerHat, true);

        // remove the 5th signer
        hatsSignerGate.removeSigner(addresses[4]);

        // signer count should be 4 and threshold at target
        assertEq(hatsSignerGate.validSignerCount(), 4, "valid signer count");
        assertEq(safe.getThreshold(), hatsSignerGate.targetThreshold(), "ending threshold");
    }

    function testCanClaimToReplaceInvalidSignerAtMaxSigner() public {
        assertEq(maxSigners, 5, "max signers");
        // start with 5 valid signers (the max)
        addSigners(5);

        // the last one loses their hat
        mockIsWearerCall(addresses[4], signerHat, false);

        // a new signer valid tries to claim, and can
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hatsSignerGate.claimSigner();
        assertEq(hatsSignerGate.validSignerCount(), 5, "valid signer count");
    }

    function testSetTargetThresholdUpdatesThresholdCorrectly() public {
        // set target threshold to 5
        mockIsWearerCall(address(this), ownerHat, true);
        hatsSignerGate.setTargetThreshold(5);
        // add 5 valid signers
        addSigners(5);
        // one loses their hat
        mockIsWearerCall(addresses[4], signerHat, false);
        // lower target threshold to 4
        hatsSignerGate.setTargetThreshold(4);
        // since hatsSignerGate.validSignerCount() is also 4, the threshold should also be 4
        assertEq(safe.getThreshold(), 4, "threshold");
    }

    function testSetTargetTresholdCannotSetBelowMinThreshold() public {
        assertEq(hatsSignerGate.minThreshold(), 2, "min threshold");
        assertEq(hatsSignerGate.targetThreshold(), 2, "target threshold");

        // set target threshold to 1 — should fail
        mockIsWearerCall(address(this), ownerHat, true);
        vm.expectRevert(InvalidTargetThreshold.selector);
        hatsSignerGate.setTargetThreshold(1);
    }

    function testCannotAccidentallySetThresholdHigherThanTarget() public {
        assertEq(hatsSignerGate.targetThreshold(), 2, "target threshold");

        // to reach the condition to test, we need...
        // 1) signer count > target threshold
        // 2) current threshold < target threshold

        // 1) its unlikely to get both of these naturally since adding new signers increases the threshold
        // but we can force it by adding owners to the safe by pretending to be the hatsSignerGate itself
        // we start by adding 1 valid signer legitimately
        addSigners(1);
        // then we add 2 more valid owners my pranking the execTransactionFromModule function
        mockIsWearerCall(addresses[2], signerHat, true);
        mockIsWearerCall(addresses[3], signerHat, true);
        bytes memory addOwner3 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[2], 1);
        bytes memory addOwner4 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[3], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.startPrank(address(hatsSignerGate));
        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwner3, // data
            Enum.Operation.Call // operation
        );
        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwner4, // data
            Enum.Operation.Call // operation
        );

        // now we've meet the necessary conditions
        assertGt(
            hatsSignerGate.validSignerCount(), hatsSignerGate.targetThreshold(), "1) signer count > target threshold"
        );
        assertLt(safe.getThreshold(), hatsSignerGate.targetThreshold(), "2) current threshold < target threshold");

        // calling reconcile should change the threshold to the target
        hatsSignerGate.reconcileSignerCount();
        assertEq(safe.getThreshold(), hatsSignerGate.targetThreshold(), "threshold == target threshold");
    }

    // function testSignersCannotChangeModules() public {
    //     //
    // }
}
