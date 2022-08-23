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

        emit log_address(address(this));
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
        testAddThreeSigners();
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

    function testAddSingleSigner() public {
        // testAddSigners(1);

        mockIsWearerCall(addresses[0], signerHat, true);

        hatsSignerGate.addSigner(addresses[0]);

        assertEq(hatsSignerGate.signerCount(), 2);

        assertEq(safe.getOwners()[0], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testAddThreeSigners() public {
        for (uint256 i = 0; i < 3; ++i) {
            // mock mint 3 addresses the signerHat
            mockIsWearerCall(addresses[i], signerHat, true);

            // add them as signers
            hatsSignerGate.addSigner(addresses[i]);
        }

        assertEq(hatsSignerGate.signerCount(), 4);

        assertEq(safe.getOwners()[0], addresses[2]);
        assertEq(safe.getOwners()[1], addresses[1]);
        assertEq(safe.getOwners()[2], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    function testAddTooManySigners() public {
        for (uint256 i = 0; i < 4; ++i) {
            // mock mint 3 addresses the signerHat
            mockIsWearerCall(addresses[i], signerHat, true);

            // add them as signers
            hatsSignerGate.addSigner(addresses[i]);
        }

        mockIsWearerCall(addresses[4], signerHat, true);

        vm.expectRevert(HatsSignerGate.MaxSignersReached.selector);

        hatsSignerGate.addSigner(addresses[4]);

        assertEq(hatsSignerGate.signerCount(), 5);

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getOwners()[1], addresses[2]);
        assertEq(safe.getOwners()[2], addresses[1]);
        assertEq(safe.getOwners()[3], addresses[0]);

        assertEq(safe.getThreshold(), 2);
    }

    // function testAddSigners(uint256 signerCount) public {
    //     // vm.assume(signerCount > 0);
    //     // vm.assume(signerCount < maxSigners);
    //     signerCount = bound(signerCount, 1, maxSigners - 1);

    //     for (uint256 i = 0; i < signerCount; ++i) {
    //         // mock mint 3 addresses the signerHat
    //         mockIsWearerCall(addresses[i], signerHat, true);

    //         // add them as signers
    //         hatsSignerGate.addSigner(addresses[i]);
    //     }

    //     assertEq(hatsSignerGate.signerCount(), signerCount + 1);

    //     assertEq(safe.getOwners()[0], addresses[0]);
    // }

    function testClaimSigner() public {
        mockIsWearerCall(addresses[3], signerHat, true);

        vm.prank(addresses[3]);
        hatsSignerGate.claimSigner();

        assertEq(safe.getOwners()[0], addresses[3]);
        assertEq(safe.getThreshold(), 2);
    }

    function testRemoveSigner() public {
        testAddSingleSigner();

        mockIsWearerCall(addresses[0], signerHat, false);

        hatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], address(this));

        assertEq(safe.getThreshold(), 1);
    }

    // function testRemoveInitSigner() public {
    //     testAddSingleSigner();

    //     hatsSignerGate.removeSigner(address(this));

    //     assertEq(safe.getOwners().length, 1);
    //     assertEq(safe.getOwners()[0], addresses[0]);

    //     assertEq(safe.getThreshold(), 1);
    // }

    function testExecTransactionByHatWearers() public {
        testAddThreeSigners();

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = .2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);
        // create tx to send some eth from safe to wherever
        bytes32 txHash = getEthTransferSafeTxHash(
            destAddress,
            transferValue,
            safe
        );
        // have each signer sign the tx
        bytes[] memory sigs = new bytes[](3);
        bytes memory signatures;
        uint8 v;
        bytes32 r;
        bytes32 s;

        for (uint256 i = 0; i < 3; ++i) {
            // sign txHash
            (v, r, s) = vm.sign((i + 1) * 100, txHash);
            // assertEq(vm.addr((i + 1) * 100), addresses[i]);
            emit log_address(vm.addr((i + 1) * 100));
            emit log_address(addresses[i]);
            emit log_address(ecrecover(txHash, v, r, s));
            // append to signatures
            // signatures = bytes.concat(signatures, r, s, bytes1(v));
            sigs[i] = bytes.concat(r, s, bytes1(v));
        }

        // janky manual sorting of signer addresses, but gnosis safe is very needy
        signatures = bytes.concat(signatures, sigs[2]);
        signatures = bytes.concat(signatures, sigs[1]);
        signatures = bytes.concat(signatures, sigs[0]);

        emit log_array(safe.getOwners());
        emit log_bytes(signatures);

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

    function testExecTransactionByNonHatWearersFails() public {
        testAddThreeSigners();

        uint256 preNonce = safe.nonce();
        uint256 preValue = 1 ether;
        uint256 transferValue = .2 ether;
        uint256 postValue = preValue - transferValue;
        address destAddress = addresses[3];
        // give the safe some eth
        hoax(address(safe), preValue);
        // create tx to send some eth from safe to wherever
        bytes32 txHash = getEthTransferSafeTxHash(
            destAddress,
            transferValue,
            safe
        );
        // have each signer sign the tx
        bytes[] memory sigs = new bytes[](3);
        bytes memory signatures;
        uint8 v;
        bytes32 r;
        bytes32 s;

        for (uint256 i = 0; i < 3; ++i) {
            // sign txHash
            (v, r, s) = vm.sign((i + 1) * 100, txHash);
            // assertEq(vm.addr((i + 1) * 100), addresses[i]);
            emit log_address(vm.addr((i + 1) * 100));
            emit log_address(addresses[i]);
            emit log_address(ecrecover(txHash, v, r, s));
            // append to signatures
            // signatures = bytes.concat(signatures, r, s, bytes1(v));
            sigs[i] = bytes.concat(r, s, bytes1(v));
        }

        // janky manual sorting of signer addresses, but gnosis safe is very needy
        signatures = bytes.concat(signatures, sigs[2]);
        signatures = bytes.concat(signatures, sigs[1]);
        signatures = bytes.concat(signatures, sigs[0]);

        emit log_array(safe.getOwners());
        emit log_bytes(signatures);

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
        // confirm it we executed by checking ETH balance changes
        assertEq(address(safe).balance, preValue);
        assertEq(destAddress.balance, 0);
        assertEq(safe.nonce(), preNonce);
        emit log_uint(address(safe).balance);
    }

    // TODO
    // function testCannotDisableModule() public {}
    // function testCannotDisableGuard() public {}
}
