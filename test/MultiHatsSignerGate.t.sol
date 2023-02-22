// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./MHSGTestSetup.t.sol";

contract MultiHatsSignerGateTest is MHSGTestSetup {
    function test_Multi_AddSingleSigner() public {
        addSigners_Multi(1);

        assertEq(multiHatsSignerGate.signerCount(), 1);
        assertEq(safe.getOwners()[0], addresses[0]);
        assertEq(safe.getThreshold(), 1);
    }

    function test_Multi_AddTwoSigners_DifferentHats() public {
        addSigners_Multi(2);

        assertEq(multiHatsSignerGate.signerCount(), 2);
        assertEq(safe.getOwners()[0], addresses[1]);
        assertEq(safe.getOwners()[1], addresses[0]);
        assertEq(safe.getThreshold(), 2);
    }

    function test_Multi_NonHatWearerCannotClaimSigner(uint256 i) public {
        vm.assume(i < 2);
        mockIsWearerCall(addresses[3], signerHats[i], false);

        vm.prank(addresses[3]);

        vm.expectRevert(abi.encodeWithSelector(NotSignerHatWearer.selector, addresses[3]));
        multiHatsSignerGate.claimSigner(signerHats[i]);
    }

    function test_Multi_CanRemoveInvalidSigner1() public {
        addSigners_Multi(1);

        mockIsWearerCall(addresses[0], signerHats[0], false);

        multiHatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], address(multiHatsSignerGate));
        assertEq(multiHatsSignerGate.signerCount(), 0);
        assertEq(safe.getThreshold(), 1);
    }

    function test_Multi_CannotRemoveValidSigner() public {
        addSigners_Multi(1);

        mockIsWearerCall(addresses[0], signerHats[0], true);

        vm.expectRevert(abi.encodeWithSelector(StillWearsSignerHat.selector, addresses[0]));

        multiHatsSignerGate.removeSigner(addresses[0]);

        assertEq(safe.getOwners().length, 1);
        assertEq(safe.getOwners()[0], addresses[0]);
        assertEq(multiHatsSignerGate.signerCount(), 1);

        assertEq(safe.getThreshold(), 1);
    }

    function test_Multi_ExecTxByHatWearers() public {
        addSigners_Multi(3);

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
    }

    function test_Multi_ExecTxByNonHatWearersReverts() public {
        addSigners_Multi(3);

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
        mockIsWearerCall(addresses[0], signerHats[0], false);
        mockIsWearerCall(addresses[1], signerHats[1], false);

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
        // assertEq(address(safe).balance, preValue); // FIXME something weird is going on with vm.hoax();
        assertEq(destAddress.balance, 0);
        assertEq(safe.nonce(), preNonce);
    }

    function test_Multi_OwnerCanAddSignerHats(uint256 count) public {
        vm.assume(count < 100);

        // create and fill an array of signer hats to add, with length = count
        uint256[] memory hats = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            hats[i] = i;
        }

        mockIsWearerCall(addresses[0], multiHatsSignerGate.ownerHat(), true);
        vm.prank(addresses[0]);

        vm.expectEmit(false, false, false, true);
        emit HSGLib.SignerHatsAdded(hats);

        multiHatsSignerGate.addSignerHats(hats);
    }

    function test_Multi_OwnerCanAddSignerHats1() public {
        test_Multi_OwnerCanAddSignerHats(1);
    }

    function test_Multi_NonOwnerCannotAddSignerHats() public {
        // create and fill an array of signer hats to add, with length = 1
        uint256[] memory hats = new uint256[](1);
        hats[0] = 1;

        mockIsWearerCall(addresses[0], multiHatsSignerGate.ownerHat(), false);
        vm.prank(addresses[0]);

        vm.expectRevert("UNAUTHORIZED");

        multiHatsSignerGate.addSignerHats(hats);
    }
}
