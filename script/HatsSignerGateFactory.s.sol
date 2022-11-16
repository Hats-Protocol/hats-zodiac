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
    string public version = "HSG Beta 5";

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
            hats,
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
    // forge script script/HatsSignerGateFactory.s.sol -f goerli --broadcast --verify

    // forge verify-contract --chain-id 100 --num-of-optimizations 1000000 --watch --constructor-args $(cast abi-encode "constructor(address,address,address,address,address,address,address,string)" 0xEb1acAa1aDE15657C55633ecB43aa98AfD23bfe7 0x72c89eb08444bc16396dd9432b3e82d956c412ec 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2 0x00000000000DC7F163742Eb4aBEf650037b1f588 "HSG Beta 5") --compiler-version v0.8.17 0x805a6567eed224fbb62512085f9a106c8cd211f3 src/HatsSignerGateFactory.sol:HatsSignerGateFactory $ETHERSCAN_KEY

    // forge verify-contract --chain-id 100 --num-of-optimizations 1000000 --watch --compiler-version v0.8.17 0xbd7090427331cae6fc8b7f0c78d5f0fd3f2b3afa src/HatsSignerGate.sol:HatsSignerGate $ETHERSCAN_KEY
}
