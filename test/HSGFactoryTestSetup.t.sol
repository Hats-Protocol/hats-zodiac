// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HatsSignerGate.sol";
import "../src/HatsSignerGateFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
import "@gnosis.pm/zodiac/factory/ModuleProxyFactory.sol";

contract HSGFactoryTestSetup is Test {
    address public gnosisFallbackLibrary = address(bytes20("fallback"));
    address public gnosisMultisendLibrary = address(new MultiSend());

    HatsSignerGateFactory public factory;
    GnosisSafe public singletonSafe = new GnosisSafe();
    GnosisSafeProxyFactory public safeFactory = new GnosisSafeProxyFactory();
    ModuleProxyFactory public moduleProxyFactory = new ModuleProxyFactory();
    GnosisSafe public safe;
    address FIRST_ADDRESS = address(0x1);

    HatsSignerGate public singletonHatsSignerGate = new HatsSignerGate();
    HatsSignerGate public hatsSignerGate;

    address public constant HATS = address(0x4a15);

    bytes32 public constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    uint256 public ownerHat;
    uint256 public signerHat;
    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public maxSigners;
    string public version;

    address[] initSafeOwners = new address[](1);

    function deploySafe(address[] memory owners, uint256 threshold)
        public
        returns (GnosisSafe)
    {
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
        return
            GnosisSafe(
                payable(
                    safeFactory.createProxyWithNonce(
                        address(singletonSafe),
                        params,
                        1
                    )
                )
            );
    }

    function deployHSGAndSafe(
        uint256 _ownerHat,
        uint256 _signerHat,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (HatsSignerGate _hatsSignerGate, GnosisSafe _safe) {
        address hsg;
        address safe_;
        (hsg, safe_) = factory.deployHatsSignerGateAndSafe(
            _ownerHat,
            _signerHat,
            _minThreshold,
            _targetThreshold,
            _maxSigners,
            1 // saltNonce
        );

        _hatsSignerGate = HatsSignerGate(hsg);
        _safe = GnosisSafe(payable(safe_));
    }
}
