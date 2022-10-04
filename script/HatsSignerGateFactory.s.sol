// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "forge-std/StdJson.sol";
import "forge-std/Test.sol";
import "../src/HatsSignerGateFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";

contract DeployHatsSignerGateFactory is Script {
    using stdJson for string;
    // deployment params to be read from DeployParams.json
    address public gnosisFallbackLibrary;
    address public gnosisMultisendLibrary;
    address public gnosisSafeProxyFactory;
    address public hats;
    address public moduleProxyFactory;
    address public safeSingleton;

    // deployment params to be set manually
    string public version = "GC Beta 1";

    function getChainKey() public returns (string memory) {
        return string.concat(".", vm.toString(block.chainid));
    }

    function setDeployParams() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/DeployParams.json");
        string memory json = vm.readFile(path);
        string memory chain = getChainKey();

        bytes memory params = json.parseRaw(chain);

        // the json is parsed in alphabetical order, so we decode it that way too
        (
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            gnosisSafeProxyFactory,
            hats,
            moduleProxyFactory,
            safeSingleton
        ) = abi.decode(
            params,
            (address, address, address, address, address, address)
        );
    }

    function run() external {
        setDeployParams();
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);

        // deploy singleton
        HatsSignerGate hsgSingleton = new HatsSignerGate();

        HatsSignerGateFactory factory = new HatsSignerGateFactory(
            address(hsgSingleton),
            address(1),
            safeSingleton,
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            gnosisSafeProxyFactory,
            moduleProxyFactory,
            version
        );

        // // uncomment to check if its working correctly when simulating
        // (address hsg, address safe) = factory.deployHatsSignerGateAndSafe(
        //     1,
        //     2,
        //     3,
        //     4,
        //     5,
        //     6
        // );
        // GnosisSafe _safe = GnosisSafe(payable(safe));
        // console2.log("safe threshold", _safe.getThreshold());
        // console2.log("hsg is module", _safe.isModuleEnabled(hsg));

        vm.stopBroadcast();
    }

    // // simulation
    // forge script script/HatsSignerGateFactory.s.sol -f gnosis

    // // actual deploy
    // forge script script/HatsSignerGateFactory.s.sol -f gnosis --broadcast --verify
}
