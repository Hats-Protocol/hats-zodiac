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

  function log(bool _verbose) public view {
    if (_verbose) {
      console2.log("HSG implementation", address(implementation));
      console2.log("HSG runtime bytecode size:", address(implementation).code.length);

      uint256 codeLength = address(implementation).code.length;
      if (codeLength > 24_576) {
        console2.log("HSG runtime bytecode margin: negative", codeLength - 24_576);
      } else {
        console2.log("HSG runtime bytecode margin: positive", 24_576 - codeLength);
      }

      console2.log("Safe singleton", safeSingleton);
      console2.log("Safe fallback library", safeFallbackLibrary);
      console2.log("Safe multisend library", safeMultisendLibrary);
      console2.log("Safe proxy factory", safeProxyFactory);
    }
  }

  function run() external virtual returns (HatsSignerGate) {
    setDeployParams();
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);

    implementation =
      new HatsSignerGate{ salt: SALT }(hats, safeSingleton, safeFallbackLibrary, safeMultisendLibrary, safeProxyFactory);

    vm.stopBroadcast();

    log(verbose);

    return implementation;
  }

  /*

  forge script script/HatsSignerGate.s.sol:DeployImplementation --via-ir -f sepolia
  forge script script/HatsSignerGate.s.sol:DeployImplementation --via-ir -f sepolia --broadcast --verify

  forge verify-contract --chain-id <chainid> --num-of-optimizations 1000000 --watch --constructor-args 0000000000000000000000003bc1a0ad72417f2d411118085256fc53cbddd13700000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec990000000000000000000000009641d764fc13c8b624c04430c7356c1c7c8102e20000000000000000000000004e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67 --compiler-version v0.8.28 0x148057884AC910Bdd93693F230C5c35a8c47CA3b src/HatsSignerGate.sol:HatsSignerGate --etherscan-api-key $ETHERSCAN_KEY

  */
}

contract MultiChainDeployImplementation is DeployImplementation {
  using stdJson for string;

  string[] public chains = ["arbitrum", "base", "celo", "gnosis", /*"mainnet",*/ "optimism", "polygon"/*, "sepolia"*/];

  function run() external override returns (HatsSignerGate) {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);

    for (uint256 i = 0; i < chains.length; i++) {
      string memory chain = chains[i];
      console2.log("\nDeploying to", chain);

      // Use forge's built-in --fork-url flag to switch networks
      vm.createSelectFork(vm.rpcUrl(chain));

      // set the params for the current chain
      setDeployParams();

      // deploy the implementation with forge's built-in CREATE2 factory
      vm.startBroadcast(deployer);
      try new HatsSignerGate{ salt: SALT }(
        hats, safeSingleton, safeFallbackLibrary, safeMultisendLibrary, safeProxyFactory
      ) returns (HatsSignerGate hsg) {
        implementation = hsg;
        log(verbose);
      } catch {
        console2.log("Deployment failed on", chain);
      }
      vm.stopBroadcast();
    }

    return implementation;
  }

  /*

  forge script script/HatsSignerGate.s.sol:MultiChainDeployImplementation --via-ir
  forge script script/HatsSignerGate.s.sol:MultiChainDeployImplementation --via-ir --broadcast --verify

  */
}

contract DeployInstance is BaseScript {
  using stdJson for string;

  address public zodiacModuleFactory;
  address public hats;
  address public implementation = 0x148057884AC910Bdd93693F230C5c35a8c47CA3b;
  address public instance;
  address public hsgGuard;
  address[] public hsgModules;
  uint256 public saltNonce = 1;

  uint256 public ownerHat = 0x000002ae00000000000000000000000000000000000000000000000000000000;
  uint256[] public signersHats = [0x000002ae00010002000000000000000000000000000000000000000000000000];
  IHatsSignerGate.ThresholdConfig public thresholdConfig =
    IHatsSignerGate.ThresholdConfig({ thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE, min: 1, target: 2 });
  address public safe = address(0);
  bool public locked = false;
  bool public claimableFor = true;

  function prepare1(
    address _implementation,
    uint256 _ownerHat,
    uint256[] memory _signersHats,
    IHatsSignerGate.ThresholdConfig memory _thresholdConfig,
    address _safe,
    bool _locked,
    bool _claimableFor,
    address _hsgGuard,
    address[] memory _hsgModules
  ) public {
    implementation = _implementation;
    ownerHat = _ownerHat;
    signersHats = _signersHats;
    thresholdConfig = _thresholdConfig;
    safe = _safe;
    locked = _locked;
    claimableFor = _claimableFor;
    hsgGuard = _hsgGuard;
    hsgModules = _hsgModules;
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
      thresholdConfig: thresholdConfig,
      locked: locked,
      claimableFor: claimableFor,
      implementation: implementation,
      hsgGuard: hsgGuard,
      hsgModules: hsgModules
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

  /*

  forge script script/HatsSignerGate.s.sol:DeployInstance --via-ir -f sepolia
  forge script script/HatsSignerGate.s.sol:DeployInstance --via-ir -f sepolia --broadcast

  */
}
