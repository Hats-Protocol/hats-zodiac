// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/Zodiac-Hats/ZodiacHats.sol";

contract DeployZodiacHats is Script {
    uint256 public ownerHatId =
        26959946667150639794667015087019630673637144422540572481103610249216;
    uint256 public signersHatId =
        27170571250487754168062851142386971538274934613341670703612232204288;
    address public avatar = 0x1EEDaFA9E61E438E201AB6c63E53DD52C908016e;
    address public hats = 0xE81597289A249aE725c2D80E7848DbFa9708c22D;
    uint8 public targetThreshold = 1;
    string public version = "0.0.1";

    function run() external {
        vm.startBroadcast();

        ZodiacHats zodiacHats = new ZodiacHats(
            ownerHatId,
            signersHatId,
            avatar,
            hats,
            targetThreshold,
            version
        );

        vm.stopBroadcast();
    }
}
