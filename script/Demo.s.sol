// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "forge-std/Test.sol";
import "../src/HatsSignerGateFactory.sol";
import "../src/HatsSignerGate.sol";
import "hats-protocol/Hats.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";

contract Demo is Script {
    Hats public hats = Hats(0x2923469A33bd2FA2Ab33c877DB81d35A9D8d60C6);
    HatsSignerGateFactory public hsgFactory = HatsSignerGateFactory(0x397DFF38c6911216fd6A806e2840De93AD10c623);
    HatsSignerGate public hsg;

    address public demoLeader; // assign this

    uint256[] admins;
    string[] details;
    uint32[] maxSupplies;
    address[] eligibilities;
    address[] toggles;
    string[] images;
    uint256[] ids;
    address[] tos;

    function run() external {       
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);

        // 1. create top hat
        uint256 tophat = hats.mintTopHat(deployer, "");

        // 2. find Core Unit hat id
        uint256 coreUnit = hats.getNextId(tophat);
        // 3. find Facilitator hat id
        uint256 facilitator = hats.getNextId(coreUnit);
        // 4. find Member hat id
        uint256 member = hats.getNextId(facilitator);

        // 5. deploy HatsSignerGate, with Core Unit hat as owner and Member hat as signer
        (address hsg_, address safe) = hsgFactory.deployHatsSignerGateAndSafe(
            coreUnit, // owner hat
            member, // signer hat
            2, // min threshold
            3, // target threshold
            5, // max signers
            block.number // saltNonce
        ); 
        hsg = HatsSignerGate(hsg_);

        // 6. create Core Unit hat, with multisig as eligibility and toggle
        // 7. create Facilitator hat, with multisig as eligibility and toggle
        // 8. create Member hat, with multisig as eligibility and toggle
        admins[0] = tophat; admins[1] = coreUnit; admins[2] = facilitator;
        details[0] = "Demo Core Unit"; details[1] = "Demo Core Unit Facilitator"; details[2] = "Demo Core Unit Member";
        maxSupplies[0] = 1; maxSupplies[1] = 1; maxSupplies[2] = 5;
        eligibilities[0]= safe; eligibilities[1]= safe; eligibilities[2]= safe; 
        toggles[0] = safe; toggles[1] = safe; toggles[2] = safe; 
        images[0] = ""; images[1] = ""; images[2] = ""; 

        hats.batchCreateHats(
            admins, // admins
            details, // details
            maxSupplies, // max supplies
            eligibilities, // eligibility
            toggles, // toggles
            images // imageURIs
        );

        // 9. mint Core Unit hat to multisig
        // 10. mint Facilitator hat to demo lead
        ids[0] = coreUnit; ids[1] = facilitator;
        tos[0] = safe; tos[1] = demoLeader;

        hats.batchMintHats(ids,tos);

        vm.stopBroadcast();
    }

    // // simulation
    // forge script script/HatsSignerGateFactory.s.sol -f goerli

    // // actual deploy
    // forge script script/HatsSignerGateFactory.s.sol -f goerli --broadcast --verify
}
