// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/HatsSignerGate.sol";
import "../src/HatsSignerGateFactory.sol";

contract DeployHatsSignerGate is Script {
    HatsSignerGateFactory public hsgFactory; // to deploy
    uint256 public ownerHatId =
        80879840001451919384001045261058892020911433267621717443310830747648;
    uint256 public signersHatId =
        80985152293120476570698963288742562453230328363022266554565141725184;
    address public safe = 0x56c7A84Cf42Cfe70BfdF14140747ffc63b96E51A;
    // address public hats = 0x245e5B56C18B18aC2d72F94C5F7bE1D52497A8aD;
    uint256 public minThreshold = 3;
    uint256 public targetThreshold = 3;
    uint256 public maxSigners = 9;
    uint256 public saltNonce = 1;
    // string public version = "MC Super Scouts Demo #1";
    // string public version = "Rinkeby test #5";

    string public version = "Cub Scouts Beta 02";

    function run() external {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);

        address hatsSignerGate = hsgFactory.deployHatsSignerGate(
            ownerHatId,
            signersHatId,
            safe,
            minThreshold,
            targetThreshold,
            maxSigners,
            saltNonce
        );

        vm.stopBroadcast();
    }

    // forge script script/HatsSignerGate.s.sol:DeployHatsSignerGate --rpc-url $RINKEBY_RPC --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast

    // forge script script/HatsSignerGate.s.sol:DeployHatsSignerGate --rpc-url $GC_RPC --private-key $PRIVATE_KEY --verify --etherscan-api-key $GNOSISSCAN_KEY --broadcast

    // forge script script/HatsSignerGate.s.sol:DeployHatsSignerGate --rpc-url $GC_RPC --verify --etherscan-api-key $GNOSISSCAN_KEY --broadcast
}
