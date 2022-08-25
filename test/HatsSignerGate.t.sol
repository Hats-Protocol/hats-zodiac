// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGTestSetup.t.sol";

contract HatsSignerGateTest is HSGTestSetup {
    // start tests
    function testSetup() public {
        assertEq(
            address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)),
            address(hatsSignerGate)
        );

        assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));

        assertEq(safe.getOwners()[0], address(this));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
    }

    function testSetTargetThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);

        hatsSignerGate.setTargetThreshold(3);

        assertEq(hatsSignerGate.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 1);
    }

    function testSetTargetThreshold3of4() public {
        testAddThreeSigners();
        mockIsWearerCall(address(this), ownerHat, true);

        hatsSignerGate.setTargetThreshold(3);

        assertEq(hatsSignerGate.targetThreshold(), 3);
        assertEq(safe.getThreshold(), 3);
    }

    function testSetTargetThreshold4of4() public {
        addSigners(3);
        mockIsWearerCall(address(this), ownerHat, true);

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
        hatsSignerGate.setMinThreshold(3);

        assertEq(hatsSignerGate.minThreshold(), 3);
    }

    function testSetInvalidMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, true);

        vm.expectRevert(HatsSignerGate.InvalidMinThreshold.selector);
        hatsSignerGate.setMinThreshold(3);
    }

    function testNonOwnerCannotSetMinThreshold() public {
        mockIsWearerCall(address(this), ownerHat, false);

        vm.expectRevert("UNAUTHORIZED");

        hatsSignerGate.setMinThreshold(1);

        assertEq(hatsSignerGate.minThreshold(), 2);
    }

    function testAddSingleSigner() public {
        addSigners(1);

        assertEq(hatsSignerGate.signerCount(), 2);

        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testAddThreeSigners() public {
        addSigners(3);

        assertEq(hatsSignerGate.signerCount(), 4);

        assertEq(safe.getOwners()[0], addresses[2]);
        assertEq(safe.getOwners()[1], addresses[1]);
        assertEq(safe.getOwners()[2], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testAddTooManySigners() public {
        addSigners(4);

        mockIsWearerCall(addresses[4], signerHat, true);

        vm.expectRevert(HatsSignerGate.MaxSignersReached.selector);

        vm.prank(addresses[4]);
        hatsSignerGate.claimSigner();

        assertEq(hatsSignerGate.signerCount(), 5);

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getOwners()[1], addresses[2]);
        assertEq(safe.getOwners()[2], addresses[1]);
        assertEq(safe.getOwners()[3], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    // function testAddSigners(uint256 signerCount) public {
    //     signerCount = bound(signerCount, 1, maxSigners - 1);

    //     addSigners(signerCount);

    //     assertEq(hatsSignerGate.signerCount(), signerCount + 1);
    // }

    function testClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, true);

        vm.prank(addresses[3]);
        hatsSignerGate.claimSigner();

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getThreshold(), 2);
    }

    function testNonHatWearerCannotClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, false);

        vm.prank(addresses[3]);

        vm.expectRevert(
            abi.encodeWithSelector(
                HatsSignerGate.NotSignerHatWearer.selector,
                addresses[3]
            )
        );
        hatsSignerGate.claimSigner();
    }

    function testRemoveSigner() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, false);

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], address(this));

        assertEq(safe.getThreshold(), 1);
    }

    function testRemoveInitNonSigner() public {
        // first, add a legit signer
        addSigners(1);

        // second, remove the init non-signer (eg the module address)
        mockIsWearerCall(address(this), signerHat, false);
        hatsSignerGate.removeSigner(address(this));

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 1);
    }

    function testRemoveSignerStillWearingHat() public {
        addSigners(1);

        mockIsWearerCall(addresses[0], signerHat, true);

        vm.expectRevert(
            abi.encodeWithSelector(
                HatsSignerGate.StillWearsSignerHat.selector,
                addresses[0]
            )
        );

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 2);
        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testExecTxByHatWearers() public {
        addSigners(3);

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = .2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3, safe);

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
        emit log_uint(address(safe).balance);
    }

    function testExecTxByNonHatWearersFails() public {
        addSigners(3);

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = .2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);
        // create tx to send some eth from safe to wherever
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 3, safe);

        // removing the hats from 2 signers
        mockIsWearerCall(addresses[0], signerHat, false);
        mockIsWearerCall(addresses[1], signerHat, false);

        // have one of the signers submit/exec the tx
        vm.prank(addresses[0]);

        vm.expectRevert(HatsSignerGate.InvalidSigners.selector);

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
        assertEq(address(safe).balance, preValue);
        assertEq(destAddress.balance, 0);
        assertEq(safe.nonce(), preNonce);
        emit log_uint(address(safe).balance);
    }

    function testExecTxByTooFewOwnersReverts() public {
        // add a legit signer
        addSigners(1);

        // remove the init owner
        mockIsWearerCall(address(this), signerHat, false);
        hatsSignerGate.removeSigner(address(this));

        // set up test values
        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = .2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);

        // have the remaining signer sign it
        // create the tx
        bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

        // have 3 signers sign it
        bytes memory signatures = createNSigsForTx(txHash, 1, safe);

        // have the legit signer exec the tx
        vm.prank(addresses[0]);

        mockIsWearerCall(addresses[0], signerHat, true);

        vm.expectRevert(
            abi.encodeWithSelector(
                HatsSignerGate.BelowMinThreshold.selector,
                hatsSignerGate.minThreshold(),
                safe.getOwners().length
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
        assertEq(address(safe).balance, preValue);
        assertEq(destAddress.balance, 0);
        assertEq(safe.nonce(), preNonce);
        emit log_uint(address(safe).balance);
    }

    function testCannotDisableModule() public {
        bytes memory disableModuleData = abi.encodeWithSignature(
            "disableModule(address,address)",
            SENTINELS,
            address(hatsSignerGate)
        );

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableModuleData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2, safe);

        mockIsWearerCall(address(this), signerHat, false);
        // hatsSignerGate.setMinThreshold(1);
        hatsSignerGate.removeSigner(address(this));

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        // generate sig

        vm.expectRevert(
            abi.encodeWithSelector(
                HatsSignerGate.CannotDisableProtectedModules.selector,
                address(hatsSignerGate)
            )
        );
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
        bytes memory disableGuardData = abi.encodeWithSignature(
            "setGuard(address)",
            address(0x0)
        );

        addSigners(2);

        bytes32 txHash = getTxHash(address(safe), 0, disableGuardData, safe);

        bytes memory signatures = createNSigsForTx(txHash, 2, safe);

        mockIsWearerCall(address(this), signerHat, false);
        hatsSignerGate.removeSigner(address(this));

        mockIsWearerCall(addresses[0], signerHat, true);
        mockIsWearerCall(addresses[1], signerHat, true);

        vm.expectRevert(
            abi.encodeWithSelector(
                HatsSignerGate.CannotDisableThisGuard.selector,
                address(hatsSignerGate)
            )
        );
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
}
