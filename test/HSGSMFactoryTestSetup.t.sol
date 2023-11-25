// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import { HatsSignerGateBase } from "../src/HatsSignerGate.sol";
import { HSGSuperMod } from "../src/HSGSuperMod.sol";
import { HSGSuperFactory } from "../src/HSGSuperFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
import "@gnosis.pm/zodiac/factory/ModuleProxyFactory.sol";

contract HSGSMFactoryTestSetup is Test {
    address public gnosisFallbackLibrary = address(bytes20("fallback"));
    address public gnosisMultisendLibrary = address(new MultiSend());

    HSGSuperFactory public factory;
    GnosisSafe public singletonSafe = new GnosisSafe();
    GnosisSafeProxyFactory public safeFactory = new GnosisSafeProxyFactory();
    ModuleProxyFactory public moduleProxyFactory = new ModuleProxyFactory();
    GnosisSafe public safe;
    address FIRST_ADDRESS = address(0x1);

    HSGSuperMod public singletonHSGSuperMod = new HSGSuperMod();
    HSGSuperMod public hsgsuper;

    address public constant HATS = address(0x4a15);

    bytes32 public constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    uint256 public constant MIN_DELAY = 100;

    uint256 public ownerHat;
    uint256 public signerHat;
    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public maxSigners;
    string public version;

    address[] initSafeOwners = new address[](1);

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

    function deployHSGSMAndSafe(
        uint256 _ownerHat,
        uint256 _signerHat,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (HSGSuperMod _hatsSignerGate, GnosisSafe _safe) {
        address hsg;
        address safe_;
        (hsg, safe_) =
             factory.deployHSGSuperModAndSafeWithTimelock(_ownerHat, _signerHat, _minThreshold, _targetThreshold, _maxSigners, MIN_DELAY);

        _hatsSignerGate = HSGSuperMod(hsg);
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

    function mockIsWearerCall(address wearer, uint256 hat, bool result) public {
        bytes memory data = abi.encodeWithSignature("isWearerOfHat(address,uint256)", wearer, hat);
        vm.mockCall(HATS, data, abi.encode(result));
    }

    function mockIsAdminCall(address admin, uint256 hat, bool result) public {
        bytes memory data = abi.encodeWithSignature("isAdminOfHat(address,uint256)", admin, hat);
        vm.mockCall(HATS, data, abi.encode(result));
    }
}
