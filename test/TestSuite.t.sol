// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { IHats } from "../lib/hats-protocol/src/Interfaces/IHats.sol";
import { HatsSignerGate, IHatsSignerGate } from "../src/HatsSignerGate.sol";
import { HatsSignerGateHarness } from "./harnesses/HatsSignerGateHarness.sol";
import { ISafe } from "../src/lib/safe-interfaces/ISafe.sol";
import { SafeProxyFactory } from "../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { Enum } from "../lib/safe-smart-account/contracts/common/Enum.sol";
import { StorageAccessible } from "../lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { ModuleProxyFactory } from "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";
import { DeployImplementation, DeployInstance } from "../script/HatsSignerGate.s.sol";
import { TestGuard } from "./mocks/TestGuard.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";

abstract contract SafeTestHelpers is Test {
  address public constant SENTINELS = address(0x1);
  mapping(address => bytes) public walletSigs;
  uint256[] public pks;
  address[] public signerAddresses;

  /*//////////////////////////////////////////////////////////////
                              SAFE TEST HELPERS
    //////////////////////////////////////////////////////////////*/

  function _getEthTransferSafeTxHash(address _to, uint256 _value, ISafe _safe) internal view returns (bytes32 txHash) {
    return _safe.getTransactionHash(
      _to,
      _value,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      _safe.nonce()
    );
  }

  function _getTxHash(address _to, uint256 _value, Enum.Operation _operation, bytes memory _data, ISafe _safe)
    internal
    view
    returns (bytes32 txHash)
  {
    return _safe.getTransactionHash(
      _to,
      _value,
      _data,
      _operation,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      _safe.nonce()
    );
  }

  function _createNSigsForTx(bytes32 _txHash, uint256 _signerCount) internal returns (bytes memory signatures) {
    uint8 v;
    bytes32 r;
    bytes32 s;
    address signer;
    uint256[] memory signers = new uint256[](_signerCount);

    for (uint256 i = 0; i < _signerCount; ++i) {
      // sign txHash
      (v, r, s) = vm.sign(pks[i], _txHash);

      signer = ecrecover(_txHash, v, r, s);

      walletSigs[signer] = bytes.concat(r, s, bytes1(v));
      signers[i] = uint256(uint160(signer));
    }
    _sort(signers, 0, int256(_signerCount - 1));

    for (uint256 i = 0; i < _signerCount; ++i) {
      address addy = address(uint160(signers[i]));
      // emit log_address(addy);
      signatures = bytes.concat(signatures, walletSigs[addy]);
    }
  }

  function _signaturesForEthTransferTx(address _to, uint256 _value, uint256 _signerCount, ISafe _safe)
    internal
    returns (bytes memory signatures)
  {
    // create tx to send some eth from safe to wherever
    bytes32 txHash = _getEthTransferSafeTxHash(_to, _value, _safe);
    // have each signer sign the tx
    // bytes[] memory sigs = new bytes[](signerCount);
    uint8 v;
    bytes32 r;
    bytes32 s;
    address signer;
    uint256[] memory signers = new uint256[](_signerCount);

    for (uint256 i = 0; i < _signerCount; ++i) {
      // sign txHash
      (v, r, s) = vm.sign(pks[i], txHash);

      signer = ecrecover(txHash, v, r, s);

      walletSigs[signer] = bytes.concat(r, s, bytes1(v));
      signers[i] = uint256(uint160(signer));
      // assert that the derived address matches what we have already stored
      assertEq(address(uint160(signers[i])), signerAddresses[i], "signer address should match");
    }

    // sort the signers to match what Safe expects
    _sort(signers, 0, int256(_signerCount - 1));

    // concat the signatures in the order that Safe expects
    for (uint256 i = 0; i < _signerCount; ++i) {
      address addr = address(uint160(signers[i]));
      signatures = bytes.concat(signatures, walletSigs[addr]);
    }
  }

  function _createAddressesFromPks(uint256 _count)
    internal
    pure
    returns (uint256[] memory pks_, address[] memory signerAddresses_)
  {
    pks_ = new uint256[](_count);
    signerAddresses_ = new address[](_count);

    for (uint256 i = 0; i < _count; ++i) {
      pks_[i] = 100 * (i + 1);
      signerAddresses_[i] = vm.addr(pks_[i]);
    }
  }

  // borrowed from https://gist.github.com/subhodi/b3b86cc13ad2636420963e692a4d896f
  function _sort(uint256[] memory _arr, int256 _left, int256 _right) internal view {
    int256 i = _left;
    int256 j = _right;
    if (i == j) return;
    uint256 pivot = _arr[uint256(_left + (_right - _left) / 2)];
    while (i <= j) {
      while (_arr[uint256(i)] < pivot) ++i;
      while (pivot < _arr[uint256(j)]) j--;
      if (i <= j) {
        (_arr[uint256(i)], _arr[uint256(j)]) = (_arr[uint256(j)], _arr[uint256(i)]);
        ++i;
        j--;
      }
    }
    if (_left < j) _sort(_arr, _left, j);
    if (i < _right) _sort(_arr, i, _right);
  }

  function _findPrevOwner(address[] memory _owners, address _owner) internal pure returns (address prevOwner) {
    prevOwner = SENTINELS;

    for (uint256 i; i < _owners.length; ++i) {
      if (_owners[i] == _owner) {
        if (i == 0) break;
        prevOwner = _owners[i - 1];
      }
    }
  }

  // borrowed from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
  function _getSafeTxHash(address _to, bytes memory _data, ISafe _safe) public view returns (bytes32 txHash) {
    return _safe.getTransactionHash(
      _to,
      0,
      _data,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      _safe.nonce()
    );
  }

  function _getSafeDelegatecallHash(address _to, bytes memory _data, ISafe _safe)
    internal
    view
    returns (bytes32 txHash)
  {
    return _safe.getTransactionHash(
      _to, 0, _data, Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(address(0)), _safe.nonce()
    );
  }

  // modified from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
  function _executeSafeTxFrom(address _from, bytes memory _data, ISafe _safe) public {
    _safe.execTransaction(
      address(_safe),
      0,
      _data,
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      // (r,s,v) [r - from] [s - unused] [v - 1 flag for onchain approval]
      abi.encode(_from, bytes32(0), bytes1(0x01))
    );
  }

  function _executeEthTransferFromSafe(address _to, uint256 _value, uint256 _signerCount, ISafe _safe) public {
    bytes32 txHash = _getEthTransferSafeTxHash(_to, _value, _safe);

    bytes memory signatures = _createNSigsForTx(txHash, _signerCount);

    _safe.execTransaction(
      address(_safe),
      _value,
      "",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );
  }
}

contract TestSuite is SafeTestHelpers {
  // Constants
  uint256 public constant TEST_SALT_NONCE = 1;
  bytes32 public constant TEST_SALT = bytes32(abi.encode(TEST_SALT_NONCE));
  bytes32 public constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

  // Test environment
  uint256 public FORK_BLOCK = 20_786_857;
  string public chain = "mainnet";

  // Test addresses
  address public org = makeAddr("org");
  address public owner = makeAddr("owner");
  address public eligibility = makeAddr("eligibility");
  address public toggle = makeAddr("toggle");
  address public other = makeAddr("other");
  address[] public fuzzingAddresses;

  // Test delegatecall targets
  address[] public defaultDelegatecallTargets;
  address public v1_3_0_callOnly_canonical = 0x40A2aCCbd92BCA938b02010E17A5b8929b49130D;
  address public v1_3_0_callOnly_eip155 = 0xA1dabEF33b3B82c7814B6D82A79e50F4AC44102B;
  address public v1_4_1_callOnly_canonical = 0x9641d764fc13c8B624c04430C7356C1C7C8102e2;

  // Test hats
  uint256 public tophat;
  uint256 public ownerHat;
  uint256[] public signerHats;
  uint256 public signerHat;

  // Dependency contract addresses
  IHats public hats;
  ISafe public singletonSafe;
  SafeProxyFactory public safeFactory;
  ModuleProxyFactory public zodiacModuleFactory;
  ISafe public safe;
  address public safeFallbackLibrary;
  address public safeMultisendLibrary;
  address public caller;

  // Contracts under test
  HatsSignerGate public implementationHSG;
  HatsSignerGate public instance;

  // Test params
  IHatsSignerGate.ThresholdConfig public thresholdConfig;
  bool public locked;
  TestGuard[] public tstGuards;
  TestGuard public tstGuard;
  address[] public tstModules;
  address public tstModule1 = makeAddr("tstModule1");
  address public tstModule2 = makeAddr("tstModule2");
  address public tstModule3 = makeAddr("tstModule3");

  // Utility variables
  address[] initSafeOwners = new address[](1);

  function setUp() public virtual {
    // Set up the test environment with a fork
    vm.createSelectFork(chain, FORK_BLOCK);

    // Deploy the HSG implementation with a salt
    DeployImplementation implementationDeployer = new DeployImplementation();
    implementationDeployer.prepare(false);
    implementationHSG = implementationDeployer.run();

    // Cache the deploy params and factory address
    safeFallbackLibrary = implementationDeployer.safeFallbackLibrary();
    safeMultisendLibrary = implementationDeployer.safeMultisendLibrary();
    safeFactory = SafeProxyFactory(implementationDeployer.safeProxyFactory());
    zodiacModuleFactory = ModuleProxyFactory(implementationDeployer.zodiacModuleFactory());
    singletonSafe = ISafe(payable(implementationDeployer.safeSingleton()));
    hats = IHats(implementationDeployer.hats());

    // Create test signer addresses
    (pks, signerAddresses) = _createAddressesFromPks(20);

    // generate fuzzing addresses
    fuzzingAddresses = _generateFuzzingAddresses(50);

    // create several test guards
    tstGuard = new TestGuard{ salt: bytes32(0) }(address(instance));
    tstGuards = new TestGuard[](3);
    tstGuards[0] = tstGuard;
    tstGuards[1] = new TestGuard{ salt: keccak256(abi.encode(1)) }(address(instance));
    tstGuards[2] = new TestGuard{ salt: keccak256(abi.encode(2)) }(address(instance));

    // set up the test modules array
    tstModules = new address[](3);
    tstModules[0] = tstModule1;
    tstModules[1] = tstModule2;
    tstModules[2] = tstModule3;

    // set up the default delegatecall targets array
    defaultDelegatecallTargets = new address[](3);
    defaultDelegatecallTargets[0] = v1_3_0_callOnly_canonical;
    defaultDelegatecallTargets[1] = v1_3_0_callOnly_eip155;
    defaultDelegatecallTargets[2] = v1_4_1_callOnly_canonical;

    // Set up the test hats
    uint256 signerHatCount = 10;
    signerHats = new uint256[](signerHatCount);

    vm.startPrank(org);
    tophat = hats.mintTopHat(org, "tophat", "https://hats.com");
    ownerHat = hats.createHat(tophat, "owner", 500, eligibility, toggle, true, "");

    for (uint256 i = 0; i < signerHatCount; ++i) {
      signerHats[i] =
        hats.createHat(tophat, string.concat("signerHat", vm.toString(i)), 500, eligibility, toggle, true, "image");
    }

    hats.mintHat(ownerHat, owner);
    vm.stopPrank();

    signerHat = signerHats[0];

    // Set default test HSG params
    thresholdConfig = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: 2,
      target: 2
    });
  }

  /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT HELPERS
    //////////////////////////////////////////////////////////////*/

  function _deploySafe(address[] memory _owners, uint256 _threshold, uint256 _saltNonce) internal returns (ISafe) {
    // encode safe setup parameters
    bytes memory params = abi.encodeWithSignature(
      "setup(address[],uint256,address,bytes,address,address,uint256,address)",
      _owners,
      _threshold,
      address(0), // to
      0x0, // data
      address(0), // fallback handler
      address(0), // payment token
      0, // payment
      address(0) // payment receiver
    );

    // deploy proxy of singleton from factory
    return ISafe(payable(safeFactory.createProxyWithNonce(address(singletonSafe), params, _saltNonce)));
  }

  function _deployHSG(
    uint256 _ownerHat,
    uint256[] memory _signerHats,
    IHatsSignerGate.ThresholdConfig memory _thresholdConfig,
    address _safe,
    bool _locked,
    bool _claimableFor,
    address _hsgGuard,
    address[] memory _hsgModules,
    bytes4 _expectedError,
    bool _verbose
  ) internal returns (HatsSignerGate) {
    // create the instance deployer
    DeployInstance instanceDeployer = new DeployInstance();
    instanceDeployer.prepare1(
      address(implementationHSG),
      _ownerHat,
      _signerHats,
      _thresholdConfig,
      _safe,
      _locked,
      _claimableFor,
      _hsgGuard,
      _hsgModules
    );
    instanceDeployer.prepare2(_verbose, TEST_SALT_NONCE);

    if (_expectedError > 0) {
      vm.expectRevert(_expectedError);
    }

    // deploy the instance
    return instanceDeployer.run();
  }

  function _deployHSGAndSafe(
    uint256 _ownerHat,
    uint256[] memory _signerHats,
    IHatsSignerGate.ThresholdConfig memory _thresholdConfig,
    bool _locked,
    bool _verbose,
    bool _claimableFor,
    address _hsgGuard,
    address[] memory _hsgModules
  ) internal returns (HatsSignerGate _instance, ISafe _safe) {
    // create the instance deployer
    DeployInstance instanceDeployer = new DeployInstance();
    instanceDeployer.prepare1(
      address(implementationHSG),
      _ownerHat,
      _signerHats,
      _thresholdConfig,
      address(0),
      _locked,
      _claimableFor,
      _hsgGuard,
      _hsgModules
    );
    instanceDeployer.prepare2(_verbose, TEST_SALT_NONCE);
    _instance = instanceDeployer.run();
    _safe = _instance.safe();
  }

  function _getSafeGuard(address _safe) internal view returns (address) {
    return abi.decode(StorageAccessible(_safe).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
  }

  /*//////////////////////////////////////////////////////////////
                        SIGNER SETTING HELPERS
    //////////////////////////////////////////////////////////////*/

  function _addSignersSameHat(uint256 _count, uint256 _hat) internal virtual {
    for (uint256 i = 0; i < _count; ++i) {
      _setSignerValidity(signerAddresses[i], _hat, true);
      vm.expectEmit();
      emit IHatsSignerGate.Registered(_hat, signerAddresses[i]);
      vm.prank(signerAddresses[i]);
      instance.claimSigner(_hat);
    }
  }

  function _addSignersDifferentHats(uint256 _count, uint256[] memory _hats) internal {
    for (uint256 i = 0; i < _count; ++i) {
      _setSignerValidity(signerAddresses[i], _hats[i], true);
      vm.prank(signerAddresses[i]);
      instance.claimSigner(_hats[i]);
    }
  }

  function _setSignerValidity(address _wearer, uint256 _hat, bool _result) internal {
    if (_result) {
      if (hats.isWearerOfHat(_wearer, _hat)) return;
      // mint the hat to the wearer
      vm.prank(org);
      hats.mintHat(_hat, _wearer);
    } else {
      // revoke the wearer's hat
      vm.prank(eligibility);
      hats.setHatWearerStatus(_hat, _wearer, false, true);
    }
  }

  /// @dev Construct the call and txHash for a single action multisend
  function _constructSingleActionMultiSendTx(bytes memory _data)
    internal
    view
    returns (bytes memory call, bytes32 txHash)
  {
    bytes memory multisendData = abi.encodePacked(
      Enum.Operation.Call, // 0 for call; 1 for delegatecall
      address(safe), // to
      uint256(0), // value
      uint256(_data.length), // data length
      _data // data
    );
    call = abi.encodeWithSelector(MultiSend.multiSend.selector, multisendData);
    txHash = _getTxHash(defaultDelegatecallTargets[0], 0, Enum.Operation.DelegateCall, call, safe);
  }

  /*//////////////////////////////////////////////////////////////
                        FUZZING HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  function _generateFuzzingAddresses(uint256 _count) internal returns (address[] memory) {
    address[] memory addresses = new address[](_count);
    for (uint256 i = 0; i < addresses.length; i++) {
      addresses[i] = makeAddr(string.concat("fuzzing-", vm.toString(i)));
    }
    return addresses;
  }

  /*//////////////////////////////////////////////////////////////
                        CUSTOM ASSERTIONS
  //////////////////////////////////////////////////////////////*/

  function assertValidSignerHats(uint256[] memory _signerHats) public view {
    for (uint256 i = 0; i < _signerHats.length; ++i) {
      assertTrue(instance.isValidSignerHat(_signerHats[i]));
    }
  }

  function assertCorrectModules(address[] memory _modules) public view {
    (address[] memory pagedModules, address next) = instance.getModulesPaginated(SENTINELS, _modules.length);
    assertEq(pagedModules.length, _modules.length);
    for (uint256 i; i < _modules.length; ++i) {
      // getModulesPaginated returns the modules in the reverse order they were added
      assertEq(_modules[i], pagedModules[_modules.length - i - 1]);
    }
    assertEq(next, SENTINELS);
  }

  function assertEq(IHatsSignerGate.ThresholdConfig memory _actual, IHatsSignerGate.ThresholdConfig memory _expected)
    public
    pure
  {
    assertEq(uint8(_actual.thresholdType), uint8(_expected.thresholdType), "incorrect threshold type");
    assertEq(_actual.min, _expected.min, "incorrect min");
    assertEq(_actual.target, _expected.target, "incorrect target");
  }

  function assertOnlyModule(ISafe _safe, address _module) public view {
    (address[] memory modules, address next) = _safe.getModulesPaginated(SENTINELS, 1);
    assertEq(modules.length, 1, "should only have one module");
    assertEq(modules[0], _module, "module should be the only module");
    assertEq(next, SENTINELS, "next should be SENTINELS");
  }

  /*//////////////////////////////////////////////////////////////
                  THRESHOLD CONFIG HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  function _createValidThresholdConfig(
    IHatsSignerGate.TargetThresholdType _thresholdType,
    uint8 _min, // keep values at least somewhat realistic
    uint16 _target // keep values at least somewhat realistic
  ) internal pure returns (IHatsSignerGate.ThresholdConfig memory) {
    // ensure the min is at least 1
    uint120 min = uint120(bound(_min, 1, type(uint8).max));

    uint120 target;
    if (_thresholdType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      // ensure the target is at least the min
      target = uint120(bound(_target, min, type(uint16).max));
    } else {
      // ensure the target is no bigger than 100% (10000)
      target = uint120(bound(_target, 1, 10_000));
    }

    console2.log("config.thresholdType", uint8(_thresholdType));
    console2.log("config.min", min);
    console2.log("config.target", target);

    return IHatsSignerGate.ThresholdConfig({ thresholdType: _thresholdType, min: min, target: target });
  }

  function _calcProportionalTargetSignatures(uint256 _ownerCount, uint120 _target) internal pure returns (uint256) {
    return ((_ownerCount * _target) + 9999) / 10_000;
  }

  /// @dev Assumes _min and _target are valid
  function _calcProportionalRequiredValidSignatures(uint256 _ownerCount, uint120 _min, uint120 _target)
    internal
    pure
    returns (uint256)
  {
    if (_ownerCount < _min) return _min;
    uint256 required = _calcProportionalTargetSignatures(_ownerCount, _target);
    if (required < _min) return _min;
    return required;
  }

  function _calcAbsoluteRequiredValidSignatures(uint256 _ownerCount, uint120 _min, uint120 _target)
    internal
    pure
    returns (uint256)
  {
    if (_ownerCount < _min) return _min;
    if (_ownerCount > _target) return _target;
    return _ownerCount;
  }

  function _calcRequiredValidSignatures(uint256 _ownerCount, IHatsSignerGate.ThresholdConfig memory _config)
    internal
    pure
    returns (uint256)
  {
    if (_config.thresholdType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      return _calcAbsoluteRequiredValidSignatures(_ownerCount, _config.min, _config.target);
    }
    return _calcProportionalRequiredValidSignatures(_ownerCount, _config.min, _config.target);
  }

  /// @dev Mocks the `isWearerOfHat` function for a given wearer and hat. Useful when testing with hat ids that are not
  /// necessarily real hats.
  function _mockHatWearer(address _wearer, uint256 _hatId, bool _isWearer) internal {
    vm.mockCall(
      address(hats), abi.encodeWithSelector(hats.isWearerOfHat.selector, _wearer, _hatId), abi.encode(_isWearer)
    );
  }

  function _getRandomBool(uint256 _seed) internal pure returns (bool) {
    return _seed % 2 == 0;
  }

  /// @dev Returns a `_count` of random signer hats, that are not necessarily real hat ids
  function _getRandomSignerHats(uint256 _count) internal returns (uint256[] memory) {
    // Bound number of hats to a semi-reasonable range
    uint256 numHats = bound(_count, 1, 50);

    // Create array of signer hats
    uint256[] memory signerHats_ = new uint256[](numHats);
    for (uint256 i; i < numHats; i++) {
      signerHats_[i] = uint256(keccak256(abi.encode(vm.randomUint(), "hat", i)));
    }
    return signerHats_;
  }

  /// @dev Returns a `_count` of randomly selected valid signer hats, sampled without replacement
  function _getRandomValidSignerHatsWithoutReplacement(uint256 _seed, uint256 _count)
    internal
    view
    returns (uint256[] memory)
  {
    _count = bound(_count, 1, signerHats.length);
    uint256[] memory selected = new uint256[](_count);
    bool[] memory used = new bool[](signerHats.length);
    uint256 selectedCount;

    while (selectedCount < _count) {
      uint256 index = _seed % signerHats.length;
      if (!used[index]) {
        selected[selectedCount] = signerHats[index];
        used[index] = true;
        selectedCount++;
      }
    }

    return selected;
  }

  /// @dev Returns a `_count` of randomly selected valid signer hats, sampled with replacement
  function _getRandomValidSignerHatsWithReplacement(uint256 _seed, uint256 _count)
    internal
    view
    returns (uint256[] memory)
  {
    _count = bound(_count, 1, signerHats.length);
    uint256[] memory signerHats_ = new uint256[](_count);
    for (uint256 i; i < _count; i++) {
      signerHats_[i] = _getRandomValidSignerHat(_seed + i);
    }
    return signerHats_;
  }

  function _getRandomValidSignerHat(uint256 _seed) internal view returns (uint256) {
    uint256 index = _seed % signerHats.length;
    return signerHats[index];
  }

  function _getRandomAddress() internal returns (address) {
    return _getRandomAddress(vm.randomUint());
  }

  function _getRandomAddress(uint256 _seed) internal view returns (address) {
    uint256 addressIndex = _seed % fuzzingAddresses.length;
    return fuzzingAddresses[addressIndex];
  }

  function _getRandomSigners(uint256 _seed, uint256 _count) internal view returns (address[] memory) {
    _count = bound(_count, 1, signerAddresses.length);
    address[] memory signers = new address[](_count);
    bool[] memory used = new bool[](signerAddresses.length);
    uint256 selectedCount;

    while (selectedCount < _count) {
      uint256 index = uint256(keccak256(abi.encode(_seed, selectedCount))) % signerAddresses.length;
      if (!used[index]) {
        signers[selectedCount] = signerAddresses[index];
        used[index] = true;
        selectedCount++;
      }
    }

    return signers;
  }

  function _getRandomAddresses(uint256 _seed, uint256 _count) internal view returns (address[] memory) {
    require(_count <= fuzzingAddresses.length, "Count exceeds available addresses");
    address[] memory addresses = new address[](_count);
    bool[] memory used = new bool[](fuzzingAddresses.length);
    uint256 selectedCount;

    while (selectedCount < _count) {
      uint256 index = uint256(keccak256(abi.encode(_seed, selectedCount))) % fuzzingAddresses.length;
      if (!used[index]) {
        addresses[selectedCount] = fuzzingAddresses[index];
        used[index] = true;
        selectedCount++;
      }
    }

    return addresses;
  }

  function _getRandomGuard(uint256 _seed) internal view returns (address) {
    uint256 guardIndex = _seed % tstGuards.length;
    return address(tstGuards[guardIndex]);
  }

  function _getSignaturesForEmptyTx(uint256 _signerCount, address _to, Enum.Operation _operation)
    internal
    returns (bytes memory)
  {
    // execute a transaction from the safe to set the nonce
    bytes32 txHash;
    if (_operation == Enum.Operation.Call) {
      txHash = _getSafeTxHash(_to, "", safe);
    } else {
      txHash = _getSafeDelegatecallHash(_to, "", safe);
    }
    return _createNSigsForTx(txHash, _signerCount);
  }

  function _executeEmptyCallFromSafe(uint256 _signerCount, address _to) internal {
    // add the signers
    _addSignersSameHat(_signerCount, signerHat);

    // execute a transaction from the safe to set the nonce
    bytes memory signatures = _getSignaturesForEmptyTx(_signerCount, _to, Enum.Operation.Call);
    safe.execTransaction(_to, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures);
  }

  function _createContractSignature(address _contractSigner) internal pure returns (bytes memory signature) {
    // r encodes the address of the contract that signed the message
    bytes32 r = bytes32(uint256(uint160(_contractSigner)));
    // s can be 0
    bytes32 s = bytes32(0);
    // v must be 0
    bytes1 v = bytes1(0);
    return abi.encodePacked(r, s, v);
  }

  function _createNContractSigs(uint256 _signerCount) internal view returns (bytes memory signatures) {
    for (uint256 i; i < _signerCount; ++i) {
      signatures = bytes.concat(signatures, _createContractSignature(signerAddresses[i]));
    }
    return signatures;
  }

  modifier callerIsOwner(bool _isOwner) {
    // randomly select a caller
    caller = _getRandomAddress();

    // mint them the owner hat
    _setSignerValidity(caller, ownerHat, _isOwner);

    _;
  }

  modifier callerIsSafe(bool _isSafe) {
    if (_isSafe) {
      caller = address(safe);
    } else {
      caller = _getRandomAddress();
    }
    _;
  }
}

contract WithHSGInstanceTest is TestSuite {
  function setUp() public virtual override {
    super.setUp();

    (instance, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _locked: false,
      _claimableFor: false,
      _hsgGuard: address(0), // no guard
      _hsgModules: new address[](0), // no modules
      _verbose: false
    });
  }

  modifier isLocked(bool _locked) {
    if (_locked && !instance.locked()) {
      vm.prank(owner);
      instance.lock();
    }
    _;
  }

  modifier isClaimableFor(bool _claimableFor) {
    if (_claimableFor && !instance.claimableFor()) {
      vm.prank(owner);
      instance.setClaimableFor(true);
    }
    _;
  }
}

contract WithHSGHarnessInstanceTest is TestSuite {
  HatsSignerGateHarness public harnessImplementation;
  HatsSignerGateHarness public harness;

  IHatsSignerGate.SetupParams public harnessSetupParams;

  function setUp() public virtual override {
    super.setUp();

    // deploy the harness implementation
    harnessImplementation = new HatsSignerGateHarness(
      address(hats),
      address(singletonSafe),
      address(safeFallbackLibrary),
      address(safeMultisendLibrary),
      address(safeFactory)
    );

    // set up the harness setup params
    harnessSetupParams = IHatsSignerGate.SetupParams({
      ownerHat: ownerHat,
      signerHats: signerHats,
      safe: address(0),
      thresholdConfig: thresholdConfig,
      locked: false,
      claimableFor: false,
      implementation: address(harnessImplementation),
      hsgGuard: address(0),
      hsgModules: new address[](0)
    });

    // deploy a harness instance
    harness = HatsSignerGateHarness(
      ModuleProxyFactory(zodiacModuleFactory).deployModule(
        address(harnessImplementation),
        abi.encodeWithSignature("setUp(bytes)", abi.encode(harnessSetupParams)),
        TEST_SALT_NONCE
      )
    );

    safe = harness.safe();
  }

  function _addSignersSameHat(uint256 _count, uint256 _hat) internal override {
    for (uint256 i = 0; i < _count; ++i) {
      _setSignerValidity(signerAddresses[i], _hat, true);
      vm.expectEmit();
      emit IHatsSignerGate.Registered(_hat, signerAddresses[i]);
      vm.prank(signerAddresses[i]);
      harness.claimSigner(_hat);
    }
  }

  /// @dev Adds a random number of non-duplicate signers to the safe, randomly selected from the fuzzing addresses
  function _addRandomSigners(uint8 _numExistingSigners) internal {
    // Ensure we have at least one existing signer
    _numExistingSigners = uint8(bound(_numExistingSigners, 1, fuzzingAddresses.length - 1));

    // Use the random seed to generate multiple indices
    uint256[] memory usedIndices = new uint256[](_numExistingSigners);
    for (uint256 i; i < _numExistingSigners; i++) {
      // Generate a new index from the random seed
      uint256 index = uint256(keccak256(abi.encode(vm.randomUint(), i))) % fuzzingAddresses.length;

      // Ensure no duplicates
      bool isDuplicate;
      for (uint256 j; j < i; j++) {
        if (usedIndices[j] == index) {
          isDuplicate = true;
          break;
        }
      }
      if (!isDuplicate) {
        usedIndices[i] = index;

        // Add the signer
        address signer = fuzzingAddresses[index];
        harness.exposed_addSigner(signer);

        assertTrue(safe.isOwner(signer), "signer should be added to the safe");
        assertFalse(safe.isOwner(address(harness)), "the harness should no longer be an owner");

        // Ensure the threshold is correct
        uint256 correctThreshold = harness.exposed_getNewThreshold(safe.getOwners().length);
        assertEq(safe.getThreshold(), correctThreshold, "the safe threshold should be correct");
      }
    }
  }

  /// @dev Helper function to generate unique signatures and track valid signers.
  /// @param _dataHash The hash to sign
  /// @param _sigCount The number of signatures to generate
  /// @param _ethSign Whether to use eth_sign
  /// @return signatures The concatenated signatures bytes
  /// @return validCount The number of valid signers
  function _generateUniqueECDSASignatures(
    bytes32 _dataHash,
    uint256 _sigCount,
    bool _ethSign,
    HatsSignerGateHarness _harness
  ) internal returns (bytes memory signatures, uint256 validCount) {
    signatures = new bytes(0);
    address[] memory signers = new address[](_sigCount);
    bool[] memory used = new bool[](signerAddresses.length);

    for (uint256 i; i < _sigCount; i++) {
      // Generate random index for selecting unused signer
      uint256 signerIndex;
      do {
        signerIndex = uint256(keccak256(abi.encode(vm.randomUint(), i))) % signerAddresses.length;
      } while (used[signerIndex]);

      // Mark this signer as used
      used[signerIndex] = true;

      // if ethSign is true, use the eth_sign prefix
      bytes32 dataHash =
        _ethSign ? keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _dataHash)) : _dataHash;

      // create a signature for the data hash from the selected signer
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[signerIndex], dataHash);

      // if ethSign is true, adjust v for the eth_sign prefix
      v = _ethSign ? v + 4 : v;

      // concatenate the components into a single bytes array
      bytes memory signature = abi.encodePacked(r, s, bytes1(v));
      assertEq(signature.length, 65, "signature length should be 65");

      // add the signature to the signatures array
      signatures = bytes.concat(signatures, signature);
      assertEq(signatures.length, (i + 1) * 65, "signatures length should 65 * number of sigs");

      // add the signer to the signers array
      signers[i] = signerAddresses[signerIndex];

      // Set validity and track expected count
      bool isValid = _getRandomBool(i);
      _setSignerValidity(signers[i], signerHat, isValid);
      if (isValid) {
        _harness.exposed_registerSigner(signerHat, signers[i], false);
        validCount++;
      }
    }
  }

  /// @dev Helper function to generate unique non-ECDSA signatures and track valid signers.
  /// @param _sigCount The number of signatures to generate
  /// @param _approvedHash Whether to use approved hash signatures (true) or contract signatures (false)
  /// @return signatures The concatenated signatures bytes
  /// @return validCount The number of valid signers
  function _generateUniqueNonECDSASignatures(uint256 _sigCount, bool _approvedHash, HatsSignerGateHarness _harness)
    internal
    returns (bytes memory signatures, uint256 validCount)
  {
    signatures = new bytes(0);
    address[] memory signers = new address[](_sigCount);
    bool[] memory used = new bool[](signerAddresses.length);

    for (uint256 i; i < _sigCount; i++) {
      // Generate random index for selecting unused signer
      uint256 signerIndex;
      do {
        signerIndex = uint256(keccak256(abi.encode(vm.randomUint(), i))) % signerAddresses.length;
      } while (used[signerIndex]);

      // Mark this signer as used
      used[signerIndex] = true;

      // encode the signer address into r
      bytes32 r = bytes32(uint256(uint160(signerAddresses[signerIndex])));
      bytes32 s = bytes32(0);

      // set v based on whether we are using approved hash signatures (v=1) or contract signatures (v=0)
      uint8 v = _approvedHash ? 1 : 0;

      // concatenate the components into a single bytes array
      bytes memory signature = abi.encodePacked(r, s, bytes1(v));
      assertEq(signature.length, 65, "signature length should be 65");

      // add the signature to the signatures array
      signatures = bytes.concat(signatures, signature);
      assertEq(signatures.length, (i + 1) * 65, "signatures length should 65 * number of sigs");

      // add the signer to the signers array
      signers[i] = signerAddresses[signerIndex];

      // Set validity and track expected count
      bool isValid = _getRandomBool(i);
      _setSignerValidity(signers[i], signerHat, isValid);
      if (isValid) {
        _harness.exposed_registerSigner(signerHat, signers[i], false);
        validCount++;
      }
    }
  }

  function _assertTransientStateVariables(
    uint256 _guardEntries,
    Enum.Operation _operation,
    bytes32 _existingOwnersHash,
    uint256 _existingThreshold,
    address _existingFallbackHandler
  ) internal view {
    assertEq(harness.guardEntries(), _guardEntries, "guard entries should be set");
    assertEq(uint8(harness.operation()), uint8(_operation), "operation should be set");
    if (_operation == Enum.Operation.DelegateCall) {
      assertEq(harness.existingOwnersHash(), _existingOwnersHash, "existing owners hash should be set");
      assertEq(harness.existingThreshold(), _existingThreshold, "existing threshold should be set");
      assertEq(harness.existingFallbackHandler(), _existingFallbackHandler, "existing fallback handler should be set");
    } else {
      assertEq(harness.existingOwnersHash(), bytes32(0), "existing owners hash should be empty");
      assertEq(harness.existingThreshold(), 0, "existing threshold should be empty");
      assertEq(harness.existingFallbackHandler(), address(0), "existing fallback handler should be empty");
    }
  }

  /// @dev Gets the existing state stored in transient storage by `_checkModuleTransaction` and asserts it matches
  /// the provided values
  function assertCorrectTransientState(
    bytes32 _existingOwnersHash,
    uint256 _existingThreshold,
    address _existingFallbackHandler
  ) internal view {
    assertEq(harness.exposed_existingOwnersHash(), _existingOwnersHash, "the existing owners hash should be unchanged");
    assertEq(harness.exposed_existingThreshold(), _existingThreshold, "the existing threshold should be unchanged");
    assertEq(
      harness.exposed_existingFallbackHandler(),
      _existingFallbackHandler,
      "the existing fallback handler should be unchanged"
    );
  }
}
