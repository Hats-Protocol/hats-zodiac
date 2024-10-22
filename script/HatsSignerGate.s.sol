// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Script, console2 } from "forge-std/Script.sol";
import { stdJson } from "forge-std/StdJson.sol";
import { HatsSignerGate } from "../src/HatsSignerGate.sol";
import { IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
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

  function prepare(bool _verbose) public {
    verbose = _verbose;
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
      console2.log("HSG runtime bytecode size", address(implementation).code.length);
      console2.log("HSG runtime bytecode margin", 24_576 - (address(implementation).code.length));
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
  address public hsgGuard;
  uint256 public saltNonce;

  uint256 public ownerHat;
  uint256[] public signersHats;
  uint256 public minThreshold;
  uint256 public targetThreshold;
  address public safe;
  bool public locked;
  bool public claimableFor;

  function prepare1(
    address _implementation,
    uint256 _ownerHat,
    uint256[] memory _signersHats,
    uint256 _minThreshold,
    uint256 _targetThreshold,
    address _safe,
    bool _locked,
    bool _claimableFor,
    address _hsgGuard
  ) public {
    implementation = _implementation;
    ownerHat = _ownerHat;
    signersHats = _signersHats;
    minThreshold = _minThreshold;
    targetThreshold = _targetThreshold;
    safe = _safe;
    locked = _locked;
    claimableFor = _claimableFor;
    hsgGuard = _hsgGuard;
  }

  function prepare2(bool _verbose, uint256 _saltNonce) public {
    verbose = _verbose;
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

  function setupParams() public view returns (IHatsSignerGate.SetupParams memory params) {
    params = IHatsSignerGate.SetupParams({
      ownerHat: ownerHat,
      signerHats: signersHats,
      safe: safe,
      minThreshold: minThreshold,
      targetThreshold: targetThreshold,
      locked: locked,
      claimableFor: claimableFor,
      implementation: implementation,
      hsgGuard: hsgGuard
    });
    return params;
  }

  function run() external returns (HatsSignerGate) {
    setModuleFactory();

    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);

    instance = ModuleProxyFactory(zodiacModuleFactory).deployModule(
      address(implementation), abi.encodeWithSignature("setUp(bytes)", abi.encode(setupParams())), saltNonce
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
