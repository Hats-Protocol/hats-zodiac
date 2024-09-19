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

contract TestSuiteSetup is Test {
    address public constant SENTINELS = address(0x1);
    IHats public constant HATS = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137);
    bytes32 public constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    uint256 public MAINNET_FORK_BLOCK = 20786857;

    bytes32 public SALT = bytes32(abi.encode(0x1));

    uint256[] public pks;
    address[] public signerAddresses;
    address public org = makeAddr("org");
    address public owner = makeAddr("owner");

    mapping(address => bytes) public walletSigs;

    uint256[] public signerHats;
    uint256 public signerHat;

    address public gnosisFallbackLibrary;
    address public gnosisMultisendLibrary;

    HatsSignerGateFactory public factory;
    GnosisSafe public singletonSafe;
    GnosisSafeProxyFactory public safeFactory;
    ModuleProxyFactory public moduleProxyFactory;
    GnosisSafe public safe;
    address FIRST_ADDRESS = address(0x1);

    address public eligibility = makeAddr("eligibility");
    address public toggle = makeAddr("toggle");

    HatsSignerGate public singletonHatsSignerGate;
    HatsSignerGate public hatsSignerGate;

    uint256 public tophat;
    uint256 public ownerHat;

    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public maxSigners;
    string public version;

    address[] initSafeOwners = new address[](1);

    function setUp() public virtual {
        // Fork mainnet
        vm.createSelectFork("mainnet", MAINNET_FORK_BLOCK);

        // deploy the implementation with a salt
        singletonHatsSignerGate = new HatsSignerGate{ salt: SALT }();

        // set up hats
        uint256 signerHatCount = 5;
        signerHats = new uint256[](signerHatCount);

        vm.startPrank(org);
        tophat = HATS.mintTopHat(org, "tophat", "https://hats.com");
        ownerHat = HATS.createHat(tophat, "owner", 10, eligibility, toggle, true, "");

        for (uint256 i = 0; i < signerHatCount; i++) {
            signerHats[i] = HATS.createHat(
                tophat, string.concat("signerHat", vm.toString(i)), 100, eligibility, toggle, true, "image"
            );
        }
        vm.stopPrank();

        signerHat = signerHats[0];

        (pks, signerAddresses) = createAddressesFromPks(10);

        // set up other params
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        version = "test";

        // deploy the HSG factory
        DeployHatsSignerGateFactory factoryDeployer = new DeployHatsSignerGateFactory();
        factoryDeployer.prepare(singletonHatsSignerGate, version);
        factoryDeployer.run();

        // cache the deploy params and factory address
        factory = HatsSignerGateFactory(factoryDeployer.factory());
        gnosisFallbackLibrary = factoryDeployer.gnosisFallbackLibrary();
        gnosisMultisendLibrary = factoryDeployer.gnosisMultisendLibrary();
        safeFactory = GnosisSafeProxyFactory(factoryDeployer.gnosisSafeProxyFactory());
        moduleProxyFactory = ModuleProxyFactory(factoryDeployer.moduleProxyFactory());
        singletonSafe = GnosisSafe(payable(factoryDeployer.safeSingleton()));
    }

    function addSignersOneHat(uint256 count, uint256 hat) internal {
        for (uint256 i = 0; i < count; i++) {
            setSignerValidity(signerAddresses[i], hat, true);
            vm.prank(signerAddresses[i]);
            hatsSignerGate.claimSigner(hat);
        }
    }

    function addSignersMultipleHats(uint256 count, uint256[] memory hats) internal {
        for (uint256 i = 0; i < count; i++) {
            setSignerValidity(signerAddresses[i], hats[i], true);
            vm.prank(signerAddresses[i]);
            hatsSignerGate.claimSigner(hats[i]);
        }
    }

    function getEthTransferSafeTxHash(address to, uint256 value, GnosisSafe _safe)
        public
        view
        returns (bytes32 txHash)
    {
        return _safe.getTransactionHash(
            to,
            value,
            hex"00",
            Enum.Operation.Call,
            // not using the refunder
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
    }

    function getTxHash(address to, uint256 value, bytes memory data, GnosisSafe _safe)
        public
        view
        returns (bytes32 txHash)
    {
        return _safe.getTransactionHash(
            to,
            value,
            data,
            Enum.Operation.Call,
            // not using the refunder
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
    }

    function createNSigsForTx(bytes32 txHash, uint256 signerCount) public returns (bytes memory signatures) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        address signer;
        uint256[] memory signers = new uint256[](signerCount);

        for (uint256 i = 0; i < signerCount; ++i) {
            // sign txHash
            (v, r, s) = vm.sign(pks[i], txHash);

            signer = ecrecover(txHash, v, r, s);

            walletSigs[signer] = bytes.concat(r, s, bytes1(v));
            signers[i] = uint256(uint160(signer));
        }
        sort(signers, 0, int256(signerCount - 1));

        for (uint256 i = 0; i < signerCount; ++i) {
            address addy = address(uint160(signers[i]));
            // emit log_address(addy);
            signatures = bytes.concat(signatures, walletSigs[addy]);
        }
    }

    function signaturesForEthTransferTx(address to, uint256 value, uint256 signerCount, GnosisSafe _safe)
        public
        returns (bytes memory signatures)
    {
        // create tx to send some eth from safe to wherever
        bytes32 txHash = getEthTransferSafeTxHash(to, value, _safe);
        // have each signer sign the tx
        // bytes[] memory sigs = new bytes[](signerCount);
        uint8 v;
        bytes32 r;
        bytes32 s;
        address signer;
        uint256[] memory signers = new uint256[](signerCount);

        for (uint256 i = 0; i < signerCount; ++i) {
            // sign txHash
            (v, r, s) = vm.sign(pks[i], txHash);

            signer = ecrecover(txHash, v, r, s);

            walletSigs[signer] = bytes.concat(r, s, bytes1(v));
            signers[i] = uint256(uint160(signer));
        }
        sort(signers, 0, int256(signerCount - 1));

        for (uint256 i = 0; i < signerCount; ++i) {
            address addy = address(uint160(signers[i]));
            // emit log_address(addy);
            signatures = bytes.concat(signatures, walletSigs[addy]);
        }
    }

    function createAddressesFromPks(uint256 count)
        public
        pure
        returns (uint256[] memory pks_, address[] memory signerAddresses_)
    {
        pks_ = new uint256[](count);
        signerAddresses_ = new address[](count);

        for (uint256 i = 0; i < count; ++i) {
            pks_[i] = 100 * (i + 1);
            signerAddresses_[i] = vm.addr(pks_[i]);
        }
    }

    // borrowed from https://gist.github.com/subhodi/b3b86cc13ad2636420963e692a4d896f
    function sort(uint256[] memory arr, int256 left, int256 right) internal {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)];
        while (i <= j) {
            while (arr[uint256(i)] < pivot) i++;
            while (pivot < arr[uint256(j)]) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (arr[uint256(j)], arr[uint256(i)]);
                i++;
                j--;
            }
        }
        if (left < j) sort(arr, left, j);
        if (i < right) sort(arr, i, right);
    }

    function findPrevOwner(address[] memory _owners, address _owner) internal pure returns (address prevOwner) {
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

    function deploySafe(address[] memory owners, uint256 threshold) public returns (GnosisSafe) {
        // encode safe setup parameters
        bytes memory params = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            threshold,
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

    function deployHSGAndSafe(
        uint256 _ownerHat,
        uint256[] memory _signerHats,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (HatsSignerGate _hatsSignerGate, GnosisSafe _safe) {
        address mhsg;
        address safe_;
        (mhsg, safe_) =
            factory.deployHatsSignerGateAndSafe(_ownerHat, _signerHats, _minThreshold, _targetThreshold, _maxSigners);

        _hatsSignerGate = HatsSignerGate(mhsg);
        _safe = GnosisSafe(payable(safe_));
    }

    // borrowed from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
    function getSafeTxHash(address to, bytes memory data, GnosisSafe _safe) public view returns (bytes32 txHash) {
        return _safe.getTransactionHash(
            to,
            0,
            data,
            Enum.Operation.Call,
            // not using the refunder
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            safe.nonce()
        );
    }

    // modified from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
    function executeSafeTxFrom(address from, bytes memory data, GnosisSafe _safe) public {
        safe.execTransaction(
            address(_safe),
            0,
            data,
            Enum.Operation.Call,
            // not using the refunder
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            // (r,s,v) [r - from] [s - unused] [v - 1 flag for onchain approval]
            abi.encode(from, bytes32(0), bytes1(0x01))
        );
    }

    function setSignerValidity(address wearer, uint256 hat, bool result) public {
        if (result) {
            if (HATS.isWearerOfHat(wearer, hat)) return;
            // mint the hat to the wearer
            vm.prank(org);
            HATS.mintHat(hat, wearer);
        } else {
            // revoke the wearer's hat
            vm.prank(eligibility);
            HATS.setHatWearerStatus(hat, wearer, false, true);
        }
    }
}
