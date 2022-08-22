// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HatsSignerGate.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

contract HSGTestSetup is Test {
    address public singletonSafe = new GnosisSafe();
    GnosisSafeProxyFactory public safeFactory = new GnosisSafeProxyFactory();
    GnosisSafe public safe;
    HatsSignerGate public hatsSignerGate;
    address HATS = address(0x4a15);
    uint256 ownerHat;
    uint256 signerHat;
    uint256 targetThreshold;
    uint256 maxSigners;

    function mockIsWearerCall(
        address wearer,
        uint256 hat,
        bool result
    ) public {
        bytes memory data = abi.encodeWithSignature(
            "isWearerOfHat(address,uint256)",
            wearer,
            hat
        );
        vm.mockCall(HATS, data, abi.encode(result));
    }

    function deploySafe(address[] owners, uint256 threshold)
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
                    safeFactory.createProxyWithNonce(singletonSafe, params, 1)
                )
            );
    }

    // borrowed from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
    function executeSafeTxFrom(
        address from,
        bytes memory data,
        GnosisSafe _safe
    ) public {
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

    function setUp() public virtual {
        // set up variables
        ownerHat = uint256(1);
        signerHat = uint256(2);
        targetThreshold = 2;
        maxSigners = 5;

        // deploy safe
        safe = deploySafe([address(this)], 1);

        // deploy hats signer gate
        hatsSignerGate = new HatsSignerGate(
            ownerHat,
            signerHat,
            address(safe),
            HATS,
            targetThreshold,
            maxSigners
        );

        // add hats signer gate as module and guard

        // encode txs
        bytes memory enableModuleData = abi.encodeWithSignature(
            "enableModule(address)",
            address(hatsSignerGate)
        );

        bytes memory setGuardData = abi.encodeWithSignature(
            "setGuard(address)",
            address(hatsSignerGate)
        );

        // execute txs
        executeSafeTxFrom(address(this), enabledModuleData, safe);
        executeSafeTxFrom(address(this), setGuardData, safe);
    }
}
