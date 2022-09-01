// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/HatsSignerGateFactory.sol";

contract DeployHatsSignerGateFactory is Script {
    // safe deployment params
    address public safeSingleton = 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552;
    address public gnosisFallbackLibrary =
        0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4;
    address public gnosisMultisendLibrary =
        0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761;
    address public gnosisSafeProxyFactory =
        0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2;

    // HatsSignerGateFactory deployment params
    address public hats = 0xF55228444742e6812535BCda350167cd965121B7;
    string public version = "rinkeby test 01";

    // HatsSignerGate deployment params
    // uint256 public ownerHatId =
    //     26959946667150639794667015087019630673637144422540572481103610249216;
    // uint256 public signersHatId =
    //     27065258958819196981364933114703301105956039517941121592357921226752;
    // address public avatar = 0x5293A41B9C4DA8966b873A8C032D74D416baA859;
    // uint256 public minThreshold = 2;
    // uint256 public targetThreshold = 3;
    // uint256 public maxSigners = 8;

    function run() external {
        vm.startBroadcast();

        HatsSignerGateFactory factory = new HatsSignerGateFactory(
            hats,
            safeSingleton,
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            gnosisSafeProxyFactory,
            // address _moduleProxyFactory,
            version
        );

        vm.stopBroadcast();
    }

    // forge script script/HatsSignerGateFactory.s.sol:DeployHatsSignerGateFactory --rpc-url $RINKEBY_RPC --private-key $PRIVATE_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast
}
