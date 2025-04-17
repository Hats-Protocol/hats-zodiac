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

  forge verify-contract --chain-id 84532 --num-of-optimizations 1000000 --watch --constructor-args
  0000000000000000000000003bc1a0ad72417f2d411118085256fc53cbddd13700000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762000000000000000000000000fd0732dc9e303f09fcef3a7388ad10a83459ec990000000000000000000000009641d764fc13c8b624c04430c7356c1c7c8102e20000000000000000000000004e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67
  --compiler-version v0.8.28 0x148057884AC910Bdd93693F230C5c35a8c47CA3b src/HatsSignerGate.sol:HatsSignerGate
  --etherscan-api-key $ETHERSCAN_KEY

  */
}

contract MultiChainDeployImplementation is DeployImplementation {
  using stdJson for string;

  string[] public chains = ["arbitrum", "base", "celo", "gnosis", /*"mainnet",*/ "optimism", "polygon" /*, "sepolia"*/ ];

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

  struct HSGData {
    uint256 ownerHat;
    uint256[] signersHats;
    IHatsSignerGate.ThresholdConfig thresholdConfig;
    address safe;
    bool locked;
    bool claimableFor;
    address hsgGuard;
    address[] modules;
    uint256 saltNonce;
  }

  uint120 public constant FIFTY_ONE_PERCENT = 5100;

  // TODO: update tophat domain with mainnet deployments
  uint256 public topHat = 0x0000044a00000000000000000000000000000000000000000000000000000000;
  uint256 public councilMemberHat = 0x0000044a00010001000100000000000000000000000000000000000000000000;
  uint256 public generalManagerHat = 0x0000044a00010002000100010000000000000000000000000000000000000000;
  uint256 public grantsSignerHat = 0x0000044a00010002000100010002000100010000000000000000000000000000;
  uint256 public treasuryAdvisorHat = 0x0000044a00010002000100010001000100030000000000000000000000000000;
  uint256 public foundationOperatorHat = 0x0000044a00010002000100010001000100010000000000000000000000000000;
  uint256 public signingDirectorHat = 0x0000044a00010002000100000000000000000000000000000000000000000000;

  HSGData public daoCouncil = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(councilMemberHat, 0, 0, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 3,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0x860a80d33E85e97888F1f0C75c6e5BBD60b48DA9,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 1
  });

  HSGData public opExMultisig = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(foundationOperatorHat, generalManagerHat, signingDirectorHat, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0xec00C25234B89a0c9B8Bba81Dd18636b1d5ebCEb,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 1
  });

  HSGData public networkEngagementFund = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(foundationOperatorHat, generalManagerHat, signingDirectorHat, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0xB6bE324BB8d75a8275f0f21fEf66C9b4ad2304AF,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 2
  });

  HSGData public bviRareOperations = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(foundationOperatorHat, generalManagerHat, signingDirectorHat, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0xc2F394a45e994bc81EfF678bDE9172e10f7c8ddc,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 3
  });

  HSGData public grantsCommittee = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(grantsSignerHat, 0, 0, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: address(0), // TODO: replace with the grants committee safe address
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 1
  });

  HSGData public rareCollection = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(foundationOperatorHat, generalManagerHat, signingDirectorHat, 0),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0x3B9FfE03ECE0938d4f8DdEa48Fd5a610F9df32fF,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 1
  });

  HSGData public foundationTreasury = HSGData({
    ownerHat: topHat,
    signersHats: createSignersHatsArray(foundationOperatorHat, generalManagerHat, signingDirectorHat, treasuryAdvisorHat),
    thresholdConfig: IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: 2,
      target: FIFTY_ONE_PERCENT
    }),
    safe: 0xe49FC32E4111578B12555B5D2855A037602ab74b,
    locked: false,
    claimableFor: true,
    hsgGuard: address(0),
    modules: new address[](0),
    saltNonce: 1
  });

  /// @dev Set this to the HSGData struct for the council to deploy
  HSGData public councilToDeploy = foundationTreasury;

  // function prepare1(
  //   address _implementation,
  //   uint256 _ownerHat,
  //   uint256[] memory _signersHats,
  //   IHatsSignerGate.ThresholdConfig memory _thresholdConfig,
  //   address _safe,
  //   bool _locked,
  //   bool _claimableFor,
  //   address _hsgGuard,
  //   address[] memory _hsgModules
  // ) public {
  //   implementation = _implementation;
  //   ownerHat = _ownerHat;
  //   signersHats = _signersHats;
  //   thresholdConfig = _thresholdConfig;
  //   safe = _safe;
  //   locked = _locked;
  //   claimableFor = _claimableFor;
  //   hsgGuard = _hsgGuard;
  //   hsgModules = _hsgModules;
  // }

  // function prepare2(bool _verbose, uint256 _saltNonce) public {
  //   verbose = _verbose;
  //   saltNonce = _saltNonce;
  // }

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
      ownerHat: councilToDeploy.ownerHat,
      signerHats: councilToDeploy.signersHats,
      safe: councilToDeploy.safe,
      thresholdConfig: councilToDeploy.thresholdConfig,
      locked: councilToDeploy.locked,
      claimableFor: councilToDeploy.claimableFor,
      implementation: implementation,
      hsgGuard: councilToDeploy.hsgGuard,
      hsgModules: councilToDeploy.modules
    });
    return params;
  }

  /// @dev Creates an array of signers hats, skipping empty hats
  function createSignersHatsArray(
    uint256 _signersHat1,
    uint256 _signersHat2,
    uint256 _signersHat3,
    uint256 _signersHat4
  ) public pure returns (uint256[] memory) {
    uint256[] memory validHats = new uint256[](4);
    uint256 count;

    if (_signersHat1 != 0) validHats[count++] = _signersHat1;
    if (_signersHat2 != 0) validHats[count++] = _signersHat2;
    if (_signersHat3 != 0) validHats[count++] = _signersHat3;
    if (_signersHat4 != 0) validHats[count++] = _signersHat4;
    uint256[] memory signersHats = new uint256[](count);
    for (uint256 i; i < count; i++) {
      signersHats[i] = validHats[i];
    }

    return signersHats;
  }

  function run() external returns (HatsSignerGate) {
    setModuleFactory();

    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);

    instance = ModuleProxyFactory(zodiacModuleFactory).deployModule(
      address(implementation),
      abi.encodeWithSignature("setUp(bytes)", abi.encode(setupParams())),
      councilToDeploy.saltNonce
    );

    vm.stopBroadcast();

    if (verbose) {
      if (councilToDeploy.safe == address(0)) {
        console2.log("new Safe deployed", address(HatsSignerGate(instance).safe()));
      }
      for (uint256 i; i < councilToDeploy.signersHats.length; i++) {
        // log the signers hats as hex strings
        console2.log("signersHat", i, vm.toString(abi.encode(councilToDeploy.signersHats[i])));
      }
    }

    return HatsSignerGate(instance);
  }

  /*

  forge script script/HatsSignerGate.s.sol:DeployInstance --via-ir -f sepolia
  forge script script/HatsSignerGate.s.sol:DeployInstance --via-ir -f sepolia --broadcast

  */
}
