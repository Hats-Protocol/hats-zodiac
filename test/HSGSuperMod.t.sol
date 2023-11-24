// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGSMTestSetup.t.sol";

contract HSGSuperModTest is HSGSMTestSetup {
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

    // function testExecTxByHatWearers() public {
    //     addSigners(3);

    //     uint256 preNonce = safe.nonce();
    //     uint256 preValue = 1 ether;
    //     uint256 transferValue = 0.2 ether;
    //     uint256 postValue = preValue - transferValue;
    //     address destAddress = addresses[3];
    //     // give the safe some eth
    //     hoax(address(safe), preValue);

    //     // create the tx
    //     bytes32 txHash = getTxHash(destAddress, transferValue, hex"00", safe);

    //     // have 3 signers sign it
    //     bytes memory signatures = createNSigsForTx(txHash, 3);

    //     // have one of the signers submit/exec the tx
    //     vm.prank(addresses[0]);
    //     safe.execTransaction(
    //         destAddress,
    //         transferValue,
    //         hex"00",
    //         Enum.Operation.Call,
    //         // not using the refunder
    //         0,
    //         0,
    //         0,
    //         address(0),
    //         payable(address(0)),
    //         signatures
    //     );
    //     // confirm it we executed by checking ETH balance changes
    //     assertEq(address(safe).balance, postValue);
    //     assertEq(destAddress.balance, transferValue);
    //     assertEq(safe.nonce(), preNonce + 1);
    //     // emit log_uint(address(safe).balance);
    // }
}
