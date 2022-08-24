// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/HatsSignerGate.sol";

contract DeployHatsSignerGate is Script {
    uint256 public ownerHatId =
        26959946667150639794667015087019630673637144422540572481103610249216;
    uint256 public signersHatId =
        27065258958819196981364933114703301105956039517941121592357921226752;
    address public avatar = 0x5293A41B9C4DA8966b873A8C032D74D416baA859;
    address public hats = 0xF55228444742e6812535BCda350167cd965121B7;
    uint256 public targetThreshold = 3;
    uint256 public maxSigners = 8;
    string public version = "MC Super Scouts Demo #1";

    function run() external {
        vm.startBroadcast();

        HatsSignerGate hatsSignerGate = new HatsSignerGate(
            ownerHatId,
            signersHatId,
            avatar,
            hats,
            targetThreshold,
            maxSigners,
            version
        );

        vm.stopBroadcast();
    }

    // forge script script/HatsSignerGate.s.sol:DeployHatsSignerGate --rpc-url $RINKEBY_RPC --private-key $PRIVATE_KEY --verify --etherscan-api-key $ETHERSCAN_KEY --broadcast
}
