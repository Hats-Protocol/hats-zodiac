// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/Test.sol";
import { IHats } from "hats-protocol/Interfaces/IHats.sol";
import { HatsSignerGate } from "../src/HatsSignerGate.sol";
import { HatsSignerGateFactory } from "../src/HatsSignerGateFactory.sol";
import { GnosisSafe } from "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import { GnosisSafeProxyFactory } from "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import { Enum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { ModuleProxyFactory } from "@gnosis.pm/zodiac/factory/ModuleProxyFactory.sol";
import { DeployHatsSignerGateFactory } from "../script/HatsSignerGateFactory.s.sol";

abstract contract SafeTestHelpers is Test {
    address public constant SENTINELS = address(0x1);
    mapping(address => bytes) public walletSigs;
    uint256[] public pks;

    /*//////////////////////////////////////////////////////////////
                              SAFE TEST HELPERS
    //////////////////////////////////////////////////////////////*/

    function _getEthTransferSafeTxHash(address _to, uint256 _value, GnosisSafe _safe)
        internal
        view
        returns (bytes32 txHash)
    {
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

    function _getTxHash(address _to, uint256 _value, bytes memory _data, GnosisSafe _safe)
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

    function _signaturesForEthTransferTx(address _to, uint256 _value, uint256 _signerCount, GnosisSafe _safe)
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
        }
        _sort(signers, 0, int256(_signerCount - 1));

        for (uint256 i = 0; i < _signerCount; ++i) {
            address addy = address(uint160(signers[i]));
            // emit log_address(addy);
            signatures = bytes.concat(signatures, walletSigs[addy]);
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
            while (_arr[uint256(i)] < pivot) i++;
            while (pivot < _arr[uint256(j)]) j--;
            if (i <= j) {
                (_arr[uint256(i)], _arr[uint256(j)]) = (_arr[uint256(j)], _arr[uint256(i)]);
                i++;
                j--;
            }
        }
        if (_left < j) _sort(_arr, _left, j);
        if (i < _right) _sort(_arr, i, _right);
    }

    function _findPrevOwner(address[] memory _owners, address _owner) internal pure returns (address prevOwner) {
        prevOwner = SENTINELS;

        for (uint256 i; i < _owners.length;) {
            if (_owners[i] == _owner) {
                if (i == 0) break;
                prevOwner = _owners[i - 1];
            }
            // shouldn't overflow given reasonable _owners array length
            unchecked {
                ++i;
            }
        }
    }

    // borrowed from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
    function _getSafeTxHash(address _to, bytes memory _data, GnosisSafe _safe) public view returns (bytes32 txHash) {
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
    function _executeSafeTxFrom(address _from, bytes memory _data, GnosisSafe _safe) public {
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
}

contract TestSuite is SafeTestHelpers {
    // Constants
    bytes32 public constant TEST_SALT = bytes32(abi.encode("test salt"));
    bytes32 public constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    // Test environment
    uint256 public FORK_BLOCK = 20786857;
    string public chain = "mainnet";

    // Test addresses
    address public org = makeAddr("org");
    address public owner = makeAddr("owner");
    address public eligibility = makeAddr("eligibility");
    address public toggle = makeAddr("toggle");
    address[] public signerAddresses;

    // Test hats
    uint256 public tophat;
    uint256 public ownerHat;
    uint256[] public signerHats;
    uint256 public signerHat;

    // Dependency contract addresses
    IHats public hats;
    HatsSignerGateFactory public factory;
    GnosisSafe public singletonSafe;
    GnosisSafeProxyFactory public safeFactory;
    ModuleProxyFactory public moduleProxyFactory;
    GnosisSafe public safe;
    address public gnosisFallbackLibrary;
    address public gnosisMultisendLibrary;

    // Contracts under test
    HatsSignerGate public singletonHatsSignerGate;
    HatsSignerGate public hatsSignerGate;

    // Test params
    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public maxSigners;
    string public version;

    // Utility variables
    address[] initSafeOwners = new address[](1);

    function setUp() public virtual {
        // Set up the test environment with a fork
        vm.createSelectFork(chain, FORK_BLOCK);

        // Deploy the HSG implementation with a salt
        singletonHatsSignerGate = new HatsSignerGate{ salt: TEST_SALT }();

        version = "test";

        // Deploy the HSG factory
        DeployHatsSignerGateFactory factoryDeployer = new DeployHatsSignerGateFactory();
        factoryDeployer.prepare({ _verbose: false, _hatsSignerGateSingleton: singletonHatsSignerGate, _version: version });
        factoryDeployer.run();

        // Cache the deploy params and factory address
        factory = HatsSignerGateFactory(factoryDeployer.factory());
        gnosisFallbackLibrary = factoryDeployer.gnosisFallbackLibrary();
        gnosisMultisendLibrary = factoryDeployer.gnosisMultisendLibrary();
        safeFactory = GnosisSafeProxyFactory(factoryDeployer.gnosisSafeProxyFactory());
        moduleProxyFactory = ModuleProxyFactory(factoryDeployer.moduleProxyFactory());
        singletonSafe = GnosisSafe(payable(factoryDeployer.safeSingleton()));
        hats = IHats(factoryDeployer.hats());

        // Create test signer addresses
        (pks, signerAddresses) = _createAddressesFromPks(10);

        // Set up the test hats
        uint256 signerHatCount = 5;
        signerHats = new uint256[](signerHatCount);

        vm.startPrank(org);
        tophat = hats.mintTopHat(org, "tophat", "https://hats.com");
        ownerHat = hats.createHat(tophat, "owner", 10, eligibility, toggle, true, "");

        for (uint256 i = 0; i < signerHatCount; i++) {
            signerHats[i] = hats.createHat(
                tophat, string.concat("signerHat", vm.toString(i)), 100, eligibility, toggle, true, "image"
            );
        }
        vm.stopPrank();

        signerHat = signerHats[0];

        // Set up default test HSG params
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;
    }

    /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT HELPERS
    //////////////////////////////////////////////////////////////*/

    function _deploySafe(address[] memory _owners, uint256 _threshold) public returns (GnosisSafe) {
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
        return GnosisSafe(payable(safeFactory.createProxyWithNonce(address(singletonSafe), params, 1)));
    }

    function _deployHSGAndSafe(
        uint256 _ownerHat,
        uint256[] memory _signerHats,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (HatsSignerGate _hatsSignerGate, GnosisSafe _safe) {
        address hsg;
        address safe_;
        (hsg, safe_) =
            factory.deployHatsSignerGateAndSafe(_ownerHat, _signerHats, _minThreshold, _targetThreshold, _maxSigners);

        _hatsSignerGate = HatsSignerGate(hsg);
        _safe = GnosisSafe(payable(safe_));
    }

    /*//////////////////////////////////////////////////////////////
                        SIGNER SETTING HELPERS
    //////////////////////////////////////////////////////////////*/

    function _addSignersSameHat(uint256 _count, uint256 _hat) internal {
        for (uint256 i = 0; i < _count; i++) {
            _setSignerValidity(signerAddresses[i], _hat, true);
            vm.prank(signerAddresses[i]);
            hatsSignerGate.claimSigner(_hat);
        }
    }

    function _addSignersDifferentHats(uint256 _count, uint256[] memory _hats) internal {
        for (uint256 i = 0; i < _count; i++) {
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
}

contract WithHSGInstanceTest is TestSuite {
    function setUp() public override {
        super.setUp();

        (hatsSignerGate, safe) = _deployHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);
    }
}
