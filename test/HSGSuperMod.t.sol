// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGSMTestSetup.t.sol";

import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

contract HSGSuperModTest is HSGSMTestSetup {
    // test canceller cancels transaction
    function testCancellerCancelsTx() public {
        mockIsWearerCall(address(this), ownerHat, true);
        addSigners(3);
        TimelockController timelock = hsgsuper.timelock();
        
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3);

        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);
        bytes32 id = hsgsuper.scheduleTransaction(
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
        
        // confirm proposal is in the timelock
        assertEq(timelock.isOperation(id), true);
        vm.prank(canceller);
        timelock.cancel(id);

        assertEq(timelock.isOperation(id), false);
    }
    // test non-canceller cancels transaction
    function testNonCancellerCancelsTx() public {
        mockIsWearerCall(address(this), ownerHat, true);
        addSigners(3);
        TimelockController timelock = hsgsuper.timelock();
        
        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3);

        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);
        bytes32 id = hsgsuper.scheduleTransaction(
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
        
        // confirm proposal is in the timelock
        assertEq(timelock.isOperation(id), true);
        vm.prank(addresses[0]);
        vm.expectRevert();
        timelock.cancel(id);

        assertEq(timelock.isOperation(id), true);
    }
    // test signers try revoking canceller
    // function testSafeCantRevokeCanceller() public {
    //     mockIsWearerCall(address(this), ownerHat, true);
    //     addSigners(3);
    //     TimelockController timelock = hsgsuper.timelock();
        
    //     uint256 transferValue = 0 ether;
    //     address destAddress = address(timelock);
    //     bytes memory input = abi.encodeCall(timelock.revokeRole, (timelock.CANCELLER_ROLE(), canceller));

    //     // create the tx
    //     bytes32 txHash = getTxHash(destAddress, transferValue, input, safe);

    //     // have 3 signers sign it
    //     bytes memory signatures = createNSigsForTx(txHash, 3);

    //     // have one of the signers submit/exec the tx
    //     vm.startPrank(addresses[0]);
    //     bytes32 id = hsgsuper.scheduleTransaction(
    //         destAddress,
    //         transferValue,
    //         input,
    //         Enum.Operation.Call,
    //         // not using the refunder
    //         0,
    //         0,
    //         0,
    //         address(0),
    //         payable(address(0)),
    //         signatures
    //     );
        
    //     // confirm proposal is in the timelock
    //     assertEq(timelock.isOperation(id), true);
    //     vm.warp(block.timestamp+MIN_DELAY);
    //     // vm.expectRevert("Something");
    //     hsgsuper.executeTimelockTransaction(
    //         destAddress,
    //         transferValue,
    //         input,
    //         Enum.Operation.Call,
    //         // not using the refunder
    //         0,
    //         0,
    //         0,
    //         address(0),
    //         payable(address(0)),
    //         signatures
    //     );
    //     vm.stopPrank();
    // }
    // test authority adds new canceller
    function testAdminTriesClawback() public {
        addSigners(1);
        mockIsWearerCall(address(this), ownerHat, true);
        mockIsAdminCall(address(this), signerHat, true);
        
        vm.deal(address(safe), 100); // sets safe's balance to 100
        
        hsgsuper.clawback(50, addresses[0]);

        assertEq(address(safe).balance, 50);
    }

    function testNonAdminTriesClawback() public {
        addSigners(1);
        mockIsWearerCall(address(this), ownerHat, true);
        mockIsAdminCall(address(this), signerHat, false);
        
        vm.deal(address(safe), 100); // sets safe's balance to 100

        vm.expectRevert("Not admin");
        hsgsuper.clawback(50, addresses[0]);
    }

    function testNonTimelockExecTxByHatWearers() public {
        addSigners(3);

        uint256 preValue = 1 ether;
        uint256 transferValue = 0.2 ether;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3);

        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);
        vm.expectRevert("Transactions must go through the timelock.");
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

    function testTimelockExecTxByHatWearers() public {
        addSigners(3);
        TimelockController timelock = hsgsuper.timelock();

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
        bytes32 id = hsgsuper.scheduleTransaction(
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
        
        // confirm proposal is in the timelock
        assertEq(timelock.isOperation(id), true);

        vm.warp(block.timestamp+MIN_DELAY); // speeds up time for proposal to be ready
        assertEq(timelock.isOperationReady(id), true);

        // execute the proposal
        hsgsuper.executeTimelockTransaction(
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

        // confirm it we executed by checking done status and ETH balance changes
        assertEq(timelock.isOperationDone(id), true);
        assertEq(address(safe).balance, postValue);
        assertEq(destAddress.balance, transferValue);
        assertEq(safe.nonce(), preNonce + 1);
        // emit log_uint(address(safe).balance);
    }

    function testSetTargetThreshold() public {
        addSigners(1);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(3);
        hsgsuper.setTargetThreshold(3);

        assertEq(hsgsuper.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 1);
    }

    function testSetTargetThreshold3of4() public {
        addSigners(4);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(3);

        hsgsuper.setTargetThreshold(3);

        assertEq(hsgsuper.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 3);
    }

    function testSetTargetThreshold4of4() public {
        addSigners(4);
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.TargetThresholdSet(4);

        hsgsuper.setTargetThreshold(4);

        assertEq(hsgsuper.targetThreshold(), 4);
        assertEq(safe.getThreshold(), 4);
    }

    function testNonOwnerHatWearerCannotSetTargetThreshold() public {
        mockIsWearerCall(address(this), ownerHat, false);

        vm.expectRevert("UNAUTHORIZED");

        hsgsuper.setTargetThreshold(3);

        assertEq(hsgsuper.targetThreshold(), 2);
        assertEq(safe.getThreshold(), 1);
    }

    function testSetMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);
        hsgsuper.setTargetThreshold(3);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.MinThresholdSet(3);

        hsgsuper.setMinThreshold(3);

        assertEq(hsgsuper.minThreshold(), 3);
    }

    function testSetInvalidMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectRevert(InvalidMinThreshold.selector);
        hsgsuper.setMinThreshold(3);
    }

    function testNonOwnerCannotSetMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, false);

        vm.expectRevert("UNAUTHORIZED");

        hsgsuper.setMinThreshold(1);

        assertEq(hsgsuper.minThreshold(), 2);
    }

    function testReconcileSignerCount() public {
        mockIsWearerCall(addresses[1], signerHat, false);
        mockIsWearerCall(addresses[2], signerHat, false);
        mockIsWearerCall(addresses[3], signerHat, false);
        // add 3 more safe owners the old fashioned way
        // 1
        bytes memory addOwnersData1 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[1], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hsgsuper));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData1, // data
            Enum.Operation.Call // operation
        );

        // 2
        bytes memory addOwnersData2 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[2], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hsgsuper));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData2, // data
            Enum.Operation.Call // operation
        );

        // 3
        bytes memory addOwnersData3 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[3], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.prank(address(hsgsuper));

        safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnersData3, // data
            Enum.Operation.Call // operation
        );

        assertEq(hsgsuper.validSignerCount(), 0);

        // set only two of them as valid signers
        mockIsWearerCall(address(hsgsuper), signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        // do the reconcile
        hsgsuper.reconcileSignerCount();

        assertEq(hsgsuper.validSignerCount(), 2);
        assertEq(safe.getThreshold(), 2);

        // now we can remove both the invalid signers with no changes to hatsSignerCount
        mockIsWearerCall(addresses[2], signerHat, false);
        hsgsuper.removeSigner(addresses[2]);
        mockIsWearerCall(addresses[3], signerHat, false);
        hsgsuper.removeSigner(addresses[3]);

        assertEq(hsgsuper.validSignerCount(), 2);
        assertEq(safe.getThreshold(), 2);
    }

    function testAddSingleSigner() public {
        addSigners(1);

        assertEq(safe.getOwners().length, 1);

        assertEq(hsgsuper.validSignerCount(), 1);

        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 1);
    }

    function testAddThreeSigners() public {
        addSigners(3);

        assertEq(hsgsuper.validSignerCount(), 3);

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
        hsgsuper.claimSigner();

        assertEq(hsgsuper.validSignerCount(), 5);

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
        hsgsuper.claimSigner();

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getThreshold(), 1);
        assertEq(safe.getOwners().length, 1);
    }

    function testOwnerClaimSignerReverts() public {
        addSigners(2);

        vm.prank(addresses[1]);

        vm.expectRevert(abi.encodeWithSelector(SignerAlreadyClaimed.selector, addresses[1]));

        hsgsuper.claimSigner();

        assertEq(hsgsuper.validSignerCount(), 2);
    }

    function testNonHatWearerCannotClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, false);

        vm.prank(addresses[3]);

        vm.expectRevert(abi.encodeWithSelector(NotSignerHatWearer.selector, addresses[3]));
        hsgsuper.claimSigner();
    }

    function testCanRemoveInvalidSigner1() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, false);

        hsgsuper.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], address(hsgsuper));
        assertEq(hsgsuper.validSignerCount(), 0);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerWhenMultipleSigners() public {
        addSigners(2);

        mockIsWearerCall(addresses[0], signerHat, false);

        // emit log_uint(hsgsuper.signerCount());

        hsgsuper.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[1]);
        assertEq(hsgsuper.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerAfterReconcile2Signers() public {
        addSigners(2);

        mockIsWearerCall(addresses[0], signerHat, false);

        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 1);

        hsgsuper.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[1]);
        assertEq(hsgsuper.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function testCanRemoveInvalidSignerAfterReconcile3PLusSigners() public {
        addSigners(3);

        mockIsWearerCall(addresses[0], signerHat, false);

        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 2);

        hsgsuper.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getOwners()[0], addresses[2]);
        assertEq(safe.getOwners()[1], addresses[1]);
        assertEq(hsgsuper.validSignerCount(), 2);

        assertEq(safe.getThreshold(), 2);
    }

    function testCannotRemoveValidSigner() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, true);

        vm.expectRevert(abi.encodeWithSelector(StillWearsSignerHat.selector, addresses[0]));

        hsgsuper.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[0]);
        assertEq(hsgsuper.validSignerCount(), 1);

        assertEq(safe.getThreshold(), 1);
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
            abi.encodeWithSelector(BelowMinThreshold.selector, hsgsuper.minThreshold(), safe.getOwners().length)
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

        hsgsuper.reconcileSignerCount();
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
            abi.encodeWithSignature("disableModule(address,address)", SENTINELS, address(hsgsuper));

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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
    }

    function testCannotDisableGuard() public {
        bytes memory disableGuardData = abi.encodeWithSignature("setGuard(address)", address(0x0));

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableGuardData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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

        
        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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
        hsgsuper.checkTransaction(
            address(0), 0, hex"00", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"00", address(0)
        );
    }

    function testCannotCallCheckAfterExecutionFromNonSafe() public {
        vm.expectRevert(NotCalledFromSafe.selector);
        hsgsuper.checkAfterExecution(hex"00", true);
    }

    function testAttackOnMaxSignerFails() public {
        // max signers is 5
        // 5 signers claim
        addSigners(5);

        // a signer misbehaves and loses the hat
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 4
        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 4);

        // a new signer claims, so signerCount is updated to 5
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hsgsuper.claimSigner();
        assertEq(hsgsuper.validSignerCount(), 5);

        // the malicious signer behaves nicely and regains the hat, but they were kicked out by the previous signer claim
        mockIsWearerCall(addresses[4], signerHat, true);

        // reoncile is called again and signerCount stays at 5
        // vm.expectRevert(MaxSignersReached.selector);
        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 5);

        // // any eligible signer can now claim at will
        // mockIsWearerCall(addresses[6], signerHat, true);
        // vm.prank(addresses[6]);
        // hsgsuper.claimSigner();
        // assertEq(hsgsuper.signerCount(), 7);
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
        hsgsuper.reconcileSignerCount();
        console2.log("A");
        assertEq(hsgsuper.validSignerCount(), 2);

        // 4) 3 more signers can be added with claimSigner()
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hsgsuper.claimSigner();
        mockIsWearerCall(addresses[6], signerHat, true);
        vm.prank(addresses[6]);
        hsgsuper.claimSigner();
        mockIsWearerCall(addresses[7], signerHat, true);
        vm.prank(addresses[7]);
        hsgsuper.claimSigner();

        console2.log("B");
        assertEq(hsgsuper.validSignerCount(), 5);
        console2.log("C");
        assertEq(safe.getOwners().length, 5);

        // 5) the 3 signers from (2) regain their validity
        mockIsWearerCall(addresses[2], signerHat, true);
        mockIsWearerCall(addresses[3], signerHat, true);
        mockIsWearerCall(addresses[4], signerHat, true);

        // but we still only have 5 owners and 5 signers
        console2.log("D");
        assertEq(hsgsuper.validSignerCount(), 5);

        console2.log("E");
        assertEq(safe.getOwners().length, 5);

        console2.log("F");
        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 5);

        // // 6) we now have x+3 signers
        // hsgsuper.reconcileSignerCount();
        // assertEq(hsgsuper.signerCount(), 8);
    }

    function testValidSignersCanClaimAfterMaxSignerLosesHat() public {
        // max signers is 5
        // 5 signers claim
        addSigners(5);

        // a signer misbehaves and loses the hat
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 4
        hsgsuper.reconcileSignerCount();

        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hsgsuper.claimSigner();
    }

    function testValidSignersCanClaimAfterLastMaxSignerLosesHat() public {
        // max signers is 5
        // 5 signers claim
        addSigners(5);

        address[] memory owners = safe.getOwners();

        // a signer misbehaves and loses the hat
        mockIsWearerCall(owners[4], signerHat, false);

        // validSignerCount is now 4
        assertEq(hsgsuper.validSignerCount(), 4);

        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        hsgsuper.claimSigner();
    }

    function testSignersCannotAddNewModules() public {
        (address[] memory modules,) = safe.getModulesPaginated(SENTINELS, 5);
        console2.log(modules.length);
        // console2.log(modules[1]);

        bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, addModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2);

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        hsgsuper.scheduleTransaction(
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
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
        hsgsuper.setTargetThreshold(5);
        // initially there are 5 signers
        addSigners(5);

        // 3 owners lose their hats
        mockIsWearerCall(addresses[2], signerHat, false);
        mockIsWearerCall(addresses[3], signerHat, false);
        mockIsWearerCall(addresses[4], signerHat, false);

        // reconcile is called, so signerCount is updated to 2
        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 2);
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
        assertEq(hsgsuper.validSignerCount(), 4);

        // reconcile is called, updating signer count to 4
        hsgsuper.reconcileSignerCount();
        assertEq(hsgsuper.validSignerCount(), 4);

        // bad signer regains their hat
        mockIsWearerCall(addresses[4], signerHat, true);
        // signer count returns to 5
        assertEq(hsgsuper.validSignerCount(), 5);

        // new valid signer tries to claim, but can't because we're already at max signers
        mockIsWearerCall(addresses[5], signerHat, true);
        vm.prank(addresses[5]);
        vm.expectRevert(MaxSignersReached.selector);
        hsgsuper.claimSigner();
    }

    function testRemoveSignerCorrectlyUpdates() public {
        assertEq(hsgsuper.targetThreshold(), 2, "target threshold");
        assertEq(maxSigners, 5, "max signers");
        // start with 5 valid signers
        addSigners(5);

        // the last two lose their hats
        mockIsWearerCall(addresses[3], signerHat, false);
        mockIsWearerCall(addresses[4], signerHat, false);

        // the 4th regains its hat
        mockIsWearerCall(addresses[3], signerHat, true);

        // remove the 5th signer
        hsgsuper.removeSigner(addresses[4]);

        // signer count should be 4 and threshold at target
        assertEq(hsgsuper.validSignerCount(), 4, "valid signer count");
        assertEq(safe.getThreshold(), hsgsuper.targetThreshold(), "ending threshold");
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
        hsgsuper.claimSigner();
        assertEq(hsgsuper.validSignerCount(), 5, "valid signer count");
    }

    function testSetTargetThresholdUpdatesThresholdCorrectly() public {
        // set target threshold to 5
        mockIsWearerCall(address(this), ownerHat, true);
        hsgsuper.setTargetThreshold(5);
        // add 5 valid signers
        addSigners(5);
        // one loses their hat
        mockIsWearerCall(addresses[4], signerHat, false);
        // lower target threshold to 4
        hsgsuper.setTargetThreshold(4);
        // since hsgsuper.validSignerCount() is also 4, the threshold should also be 4
        assertEq(safe.getThreshold(), 4, "threshold");
    }

    function testSetTargetTresholdCannotSetBelowMinThreshold() public {
        assertEq(hsgsuper.minThreshold(), 2, "min threshold");
        assertEq(hsgsuper.targetThreshold(), 2, "target threshold");

        // set target threshold to 1 — should fail
        mockIsWearerCall(address(this), ownerHat, true);
        vm.expectRevert(InvalidTargetThreshold.selector);
        hsgsuper.setTargetThreshold(1);
    }

    function testCannotAccidentallySetThresholdHigherThanTarget() public {
        assertEq(hsgsuper.targetThreshold(), 2, "target threshold");

        // to reach the condition to test, we need...
        // 1) signer count > target threshold
        // 2) current threshold < target threshold

        // 1) its unlikely to get both of these naturally since adding new signers increases the threshold
        // but we can force it by adding owners to the safe by pretending to be the hsgsuper itself
        // we start by adding 1 valid signer legitimately
        addSigners(1);
        // then we add 2 more valid owners my pranking the execTransactionFromModule function
        mockIsWearerCall(addresses[2], signerHat, true);
        mockIsWearerCall(addresses[3], signerHat, true);
        bytes memory addOwner3 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[2], 1);
        bytes memory addOwner4 = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", addresses[3], 1);

        // mockIsWearerCall(address(this), signerHat, true);
        vm.startPrank(address(hsgsuper));
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
            hsgsuper.validSignerCount(), hsgsuper.targetThreshold(), "1) signer count > target threshold"
        );
        assertLt(safe.getThreshold(), hsgsuper.targetThreshold(), "2) current threshold < target threshold");

        // calling reconcile should change the threshold to the target
        hsgsuper.reconcileSignerCount();
        assertEq(safe.getThreshold(), hsgsuper.targetThreshold(), "threshold == target threshold");
    }

    function testAttackerCannotExploitSigHandlingDifferences() public {
        // start with 4 valid signers
        addSigners(4);
        // set target threshold (and therefore actual threshold) to 3
        mockIsWearerCall(address(this), ownerHat, true);
        hsgsuper.setTargetThreshold(3);
        assertEq(safe.getThreshold(), 3, "initial threshold");
        assertEq(safe.nonce(), 0, "pre nonce");
        // invalidate the 3rd signer, who will be our attacker
        address attacker = addresses[2];
        mockIsWearerCall(attacker, signerHat, false);

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
        bytes memory sigs = createNSigsForTx(txHash, 3);

        // attacker adds a contract signature from the 4th signer from a previous tx
        // since HSG doesn't check that the correct data was signed, it would be considered a valid signature
        bytes memory contractSig = abi.encode(addresses[3], bytes32(0), bytes1(0x01));
        sigs = bytes.concat(sigs, contractSig);

        // mock the maliciousTx so it would succeed if it were to be executed
        vm.mockCall(maliciousContract, maliciousTx, abi.encode(true));
        // attacker submits the tx to the safe, but it should fail
        vm.expectRevert(InvalidSigners.selector);
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
        assertEq(hsgsuper.validSignerCount(), 3, "valid signer count");
        assertEq(safe.nonce(), 0, "post nonce hasn't changed");
    }

    function testSignersCannotReenterCheckTransactionToAddOwners() public {
        address newOwner = makeAddr("newOwner");
        bytes memory addOwnerAction;
        bytes memory sigs;
        bytes memory checkTxAction;
        bytes memory multisend;
        // start with 3 valid signers
        addSigners(3);
        // attacker is the first of these signers
        address attacker = addresses[0];
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
        mockIsWearerCall(newOwner, signerHat, true);
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
            sigs = createNSigsForTx(dummyTxHash, 2);

            checkTxAction = abi.encodeWithSelector(
                hsgsuper.checkTransaction.selector,
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
                hsgsuper, // to
                uint256(0), // value
                uint256(checkTxAction.length), // data length
                bytes(checkTxAction) // data
            );
            multisend = abi.encodeWithSignature("multiSend(bytes)", packedCalls);
        }

        // now get the safe tx hash and have attacker sign it with a collaborator
        bytes32 safeTxHash = safe.getTransactionHash(
            gnosisMultisendLibrary, // to
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
        sigs = createNSigsForTx(safeTxHash, 2);

        // now submit the tx to the safe
        vm.prank(attacker);
        /* 
        Expect revert because of re-entry into checkTransaction
        While hsgsuper will throw the NoReentryAllowed error, 
        since the error occurs within the context of the safe transaction, 
        the safe will catch the error and re-throw with its own error, 
        ie `GS013` ("Safe transaction failed when gasPrice and safeTxGas were 0")

        Since timelock change, it will actually throw "TimelockController: underlying transaction reverted"
        */

        hsgsuper.scheduleTransaction(
            gnosisMultisendLibrary,
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
        vm.warp(block.timestamp+MIN_DELAY);
        vm.expectRevert("TimelockController: underlying transaction reverted");
        hsgsuper.executeTimelockTransaction(
            gnosisMultisendLibrary,
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
