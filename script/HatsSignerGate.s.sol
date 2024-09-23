// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { HatsSignerGate } from "../src/HatsSignerGate.sol";
import { ModuleProxyFactory } from "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";

contract BaseScript is Script {
  bool public verbose = true;

  function getChainKey() internal view returns (string memory) {
    return string.concat(".", vm.toString(block.chainid));
  }
}

contract DeployImplementation is BaseScript {
  using stdJson for string;

  address public hats;
  address public safeFallbackLibrary;
  address public safeMultisendLibrary;
  address public safeProxyFactory;
  address public safeSingleton;
  address public zodiacModuleFactory;

  HatsSignerGate public implementation;

  /// ===========================================
  /// @dev deployment params to be set manually
  string public version = "v2.0.0-test";
  bytes32 public SALT = bytes32(abi.encode(0x4a75)); // ~ H(4) A(a) T(7) S(6)
  /// ===========================================

  function setDeployParams() public {
    string memory root = vm.projectRoot();
    string memory path = string.concat(root, "/script/DeployParams.json");
    string memory json = vm.readFile(path);
    string memory chain = getChainKey();

    bytes memory params = json.parseRaw(chain);

    // the json is parsed in alphabetical order, so we decode it that way too
    (hats, safeFallbackLibrary, safeMultisendLibrary, safeProxyFactory, safeSingleton, zodiacModuleFactory) =
      abi.decode(params, (address, address, address, address, address, address));
  }

  function prepare(bool _verbose, string memory _version) public {
    verbose = _verbose;
    version = _version;
  }

  function run() external returns (HatsSignerGate) {
    setDeployParams();
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);

    implementation =
      new HatsSignerGate(hats, safeSingleton, safeFallbackLibrary, safeMultisendLibrary, safeProxyFactory);

    vm.stopBroadcast();

    if (verbose) {
      console2.log("HSG implementation", address(implementation));
      console2.log("Safe singleton", safeSingleton);
      console2.log("Safe fallback library", safeFallbackLibrary);
      console2.log("Safe multisend library", safeMultisendLibrary);
      console2.log("Safe proxy factory", safeProxyFactory);
    }

    return implementation;
  }
}

contract DeployInstance is BaseScript {
  using stdJson for string;

  address public zodiacModuleFactory;
  address public hats;
  address public implementation;
  address public instance;

  uint256 public saltNonce;

  uint256 public ownerHat;
  uint256[] public signersHats;
  uint256 public minThreshold;
  uint256 public targetThreshold;
  uint256 public maxSigners;
  address public safe;
  string public version;

  function prepare(
    bool _verbose,
    address _implementation,
    uint256 _ownerHat,
    uint256[] memory _signersHats,
    uint256 _minThreshold,
    uint256 _targetThreshold,
    uint256 _maxSigners,
    address _safe,
    string memory _version,
    uint256 _saltNonce
  ) public {
    verbose = _verbose;
    implementation = _implementation;
    ownerHat = _ownerHat;
    signersHats = _signersHats;
    minThreshold = _minThreshold;
    targetThreshold = _targetThreshold;
    maxSigners = _maxSigners;
    safe = _safe;
    version = _version;
    saltNonce = _saltNonce;
  }

  function setModuleFactory() public {
    string memory root = vm.projectRoot();
    string memory path = string.concat(root, "/script/DeployParams.json");
    string memory json = vm.readFile(path);
    string memory chain = getChainKey();

    bytes memory params = json.parseRaw(chain);

    // the json is parsed in alphabetical order, so we decode it that way too
    (,,,,, zodiacModuleFactory) = abi.decode(params, (address, address, address, address, address, address));
  }

  function createDeployParams() public view returns (bytes memory) {
    return abi.encode(ownerHat, signersHats, safe, minThreshold, targetThreshold, maxSigners, version);
  }

  function run() external returns (HatsSignerGate) {
    setModuleFactory();

    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);

    instance = ModuleProxyFactory(zodiacModuleFactory).deployModule(
      address(implementation), abi.encodeWithSignature("setUp(bytes)", createDeployParams()), saltNonce
    );

    vm.stopBroadcast();

    if (verbose) {
      if (safe == address(0)) {
        console2.log("new Safe deployed", address(HatsSignerGate(instance).safe()));
      }
    }

    return HatsSignerGate(instance);
  }
}
