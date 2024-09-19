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

    HatsSignerGate public hsgSingleton;
    HatsSignerGateFactory public factory;

    /// ===========================================
    /// @dev deployment params to be set manually
    string public version = "1.2-beta";
    bytes32 public SALT = bytes32(abi.encode(0x4a76)); // ~ H(4) A(a) T(7) S(6)

    /// ===========================================

    function getChainKey() public view returns (string memory) {
        return string.concat(".", vm.toString(block.chainid));
    }

    function setDeployParams() public {
        string memory root = vm.projectRoot();
        string memory path = string.concat(root, "/script/DeployParams.json");
        string memory json = vm.readFile(path);
        string memory chain = getChainKey();

        bytes memory params = json.parseRaw(chain);

        // the json is parsed in alphabetical order, so we decode it that way too
        (gnosisFallbackLibrary, gnosisMultisendLibrary, gnosisSafeProxyFactory, hats, moduleProxyFactory, safeSingleton)
        = abi.decode(params, (address, address, address, address, address, address));
    }

    function prepare(HatsSignerGate _hatsSignerGateSingleton, string memory _version) public {
        hsgSingleton = _hatsSignerGateSingleton;
        version = _version;
    }

    function run() external {
        setDeployParams();
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        // console2.log("deployer", deployer);
        console2.log("deployer balance (wei):", deployer.balance);
        vm.startBroadcast(deployer);

        if (address(hsgSingleton) == address(0)) {
            // deploy singletons
            hsgSingleton = new HatsSignerGate{ salt: SALT }();
        }

        // deploy factory
        factory = new HatsSignerGateFactory{ salt: SALT }(
            address(hsgSingleton),
            hats,
            safeSingleton,
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            gnosisSafeProxyFactory,
            moduleProxyFactory,
            version
        );

        vm.stopBroadcast();

        console.log("factory address", address(factory));
        console.log("hsg address", address(hsgSingleton));

        // uncomment to check if its working correctly when simulating
        // (address hsg, address safe) = factory.deployHatsSignerGateAndSafe(1, 2, 3, 4, 5);
        // GnosisSafe _safe = GnosisSafe(payable(safe));
        // console2.log("safe threshold", _safe.getThreshold());
        // console2.log("hsg is module", _safe.isModuleEnabled(hsg));
    }

    // // simulation
    // forge script script/HatsSignerGateFactory.s.sol:DeployHatsSignerGateFactory -f gnosis

    // // actual deploy
    // forge script script/HatsSignerGateFactory.s.sol -f goerli --broadcast --verify

    // forge verify-contract --chain-id 5 --num-of-optimizations 1000000 --watch --constructor-args $(cast abi-encode "constructor(address,address,address,address,address,address,address,address,string)" 0x844b3c7781338D3308Eb8D64727033893fcE1432 0xca9d698adb4052ac7751019d69582950b1e42b43 0x9D2dfd6066d5935267291718E8AA16C8Ab729E9d 0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552 0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4 0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761 0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2 0x00000000000DC7F163742Eb4aBEf650037b1f588 "1.0-beta") --compiler-version v0.8.17 0x5Ba1E49a2efCd5589422FdF1F6BCE37e4A288611 src/HatsSignerGateFactory.sol:HatsSignerGateFactory --etherscan-api-key $ETHERSCAN_KEY

    // forge verify-contract --chain-id 5 --num-of-optimizations 1000000 --watch --compiler-version v0.8.17 0xca9d698adb4052ac7751019d69582950b1e42b43 src/MultiHatsSignerGate.sol:MultiHatsSignerGate --etherscan-api-key $ETHERSCAN_KEY
}
