// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { IHats } from "../lib/hats-protocol/src/Interfaces/IHats.sol";
import { HatsSignerGate } from "../src/HatsSignerGate.sol";
import { ISafe } from "../src/lib/safe-interfaces/ISafe.sol";
import { SafeProxyFactory } from "../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { Enum } from "../lib/safe-smart-account/contracts/common/Enum.sol";
import { StorageAccessible } from "../lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { ModuleProxyFactory } from "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";
import { DeployImplementation, DeployInstance } from "../script/HatsSignerGate.s.sol";
import { TestGuard } from "./mocks/TestGuard.sol";

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

  function _getTxHash(address _to, uint256 _value, bytes memory _data, ISafe _safe)
    internal
    view
    returns (bytes32 txHash)
  {
    return _safe.getTransactionHash(
      _to,
      _value,
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

  // Contracts under test
  HatsSignerGate public singletonHatsSignerGate;
  HatsSignerGate public hatsSignerGate;

  // Test params
  uint256 public minThreshold;
  uint256 public targetThreshold;
  bool public locked;
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
    singletonHatsSignerGate = implementationDeployer.run();

    // Cache the deploy params and factory address
    safeFallbackLibrary = implementationDeployer.safeFallbackLibrary();
    safeMultisendLibrary = implementationDeployer.safeMultisendLibrary();
    safeFactory = SafeProxyFactory(implementationDeployer.safeProxyFactory());
    zodiacModuleFactory = ModuleProxyFactory(implementationDeployer.zodiacModuleFactory());
    singletonSafe = ISafe(payable(implementationDeployer.safeSingleton()));
    hats = IHats(implementationDeployer.hats());

    // Create test signer addresses
    (pks, signerAddresses) = _createAddressesFromPks(10);

    // create the test guard
    tstGuard = new TestGuard(address(hatsSignerGate));

    // set up the test modules array
    tstModules = new address[](3);
    tstModules[0] = tstModule1;
    tstModules[1] = tstModule2;
    tstModules[2] = tstModule3;

    // Set up the test hats
    uint256 signerHatCount = 5;
    signerHats = new uint256[](signerHatCount);

    vm.startPrank(org);
    tophat = hats.mintTopHat(org, "tophat", "https://hats.com");
    ownerHat = hats.createHat(tophat, "owner", 10, eligibility, toggle, true, "");

    for (uint256 i = 0; i < signerHatCount; ++i) {
      signerHats[i] =
        hats.createHat(tophat, string.concat("signerHat", vm.toString(i)), 100, eligibility, toggle, true, "image");
    }

    hats.mintHat(ownerHat, owner);
    vm.stopPrank();

    signerHat = signerHats[0];

    // Set default test HSG params
    minThreshold = 2;
    targetThreshold = 2;
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
    uint256 _minThreshold,
    uint256 _targetThreshold,
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
      address(singletonHatsSignerGate),
      _ownerHat,
      _signerHats,
      _minThreshold,
      _targetThreshold,
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
    uint256 _minThreshold,
    uint256 _targetThreshold,
    bool _locked,
    bool _verbose,
    bool _claimableFor,
    address _hsgGuard,
    address[] memory _hsgModules
  ) internal returns (HatsSignerGate _hatsSignerGate, ISafe _safe) {
    // create the instance deployer
    DeployInstance instanceDeployer = new DeployInstance();
    instanceDeployer.prepare1(
      address(singletonHatsSignerGate),
      _ownerHat,
      _signerHats,
      _minThreshold,
      _targetThreshold,
      address(0),
      _locked,
      _claimableFor,
      _hsgGuard,
      _hsgModules
    );
    instanceDeployer.prepare2(_verbose, TEST_SALT_NONCE);
    _hatsSignerGate = instanceDeployer.run();
    _safe = _hatsSignerGate.safe();
  }

  function _getSafeGuard(address _safe) internal view returns (address) {
    return abi.decode(StorageAccessible(_safe).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
  }

  /*//////////////////////////////////////////////////////////////
                        SIGNER SETTING HELPERS
    //////////////////////////////////////////////////////////////*/

  function _addSignersSameHat(uint256 _count, uint256 _hat) internal {
    for (uint256 i = 0; i < _count; ++i) {
      _setSignerValidity(signerAddresses[i], _hat, true);
      vm.prank(signerAddresses[i]);
      hatsSignerGate.claimSigner(_hat);
    }
  }

  function _addSignersDifferentHats(uint256 _count, uint256[] memory _hats) internal {
    for (uint256 i = 0; i < _count; ++i) {
      _setSignerValidity(signerAddresses[i], _hats[i], true);
      vm.prank(signerAddresses[i]);
      hatsSignerGate.claimSigner(_hats[i]);
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

  function assertValidSignerHats(uint256[] memory _signerHats) public view {
    for (uint256 i = 0; i < _signerHats.length; ++i) {
      assertTrue(hatsSignerGate.validSignerHats(_signerHats[i]));
    }
  }
}

contract WithHSGInstanceTest is TestSuite {
  function setUp() public virtual override {
    super.setUp();

    (hatsSignerGate, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _minThreshold: minThreshold,
      _targetThreshold: targetThreshold,
      _locked: false,
      _claimableFor: false,
      _hsgGuard: address(0), // no guard
      _hsgModules: new address[](0), // no modules
      _verbose: false
    });
  }
}
