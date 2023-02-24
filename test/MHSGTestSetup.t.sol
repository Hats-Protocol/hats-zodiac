// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGTestSetup.t.sol";
import "../src/HSGLib.sol";
import "@gnosis.pm/safe-contracts/contracts/common/SignatureDecoder.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

contract MHSGTestSetup is HSGTestSetup {
    uint256[] public signerHats;

    function setUp() public override {
        // set up variables
        ownerHat = 1;
        signerHats = new uint256[](5);
        signerHats[0] = 2;
        signerHats[1] = 3;
        signerHats[2] = 4;
        signerHats[3] = 5;
        signerHats[4] = 6;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        (pks, addresses) = createAddressesFromPks(6);

        version = "1.0";

        factory = new HatsSignerGateFactory(
            address(singletonHatsSignerGate),
            address(singletonMultiHatsSignerGate),
            HATS,
            address(singletonSafe),
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            address(safeFactory),
            address(moduleProxyFactory),
            version
        );

        (multiHatsSignerGate, safe) = deployMHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);
    }

    function addSigners_Multi(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            console2.log("signersHats[i]", signerHats[i]);
            mockIsWearerCall(addresses[i], signerHats[i], true);
            vm.prank(addresses[i]);
            multiHatsSignerGate.claimSigner(signerHats[i]);
        }
    }
}
