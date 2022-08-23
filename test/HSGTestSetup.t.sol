// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/HatsSignerGate.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

contract HSGTestSetup is Test {
    GnosisSafe public singletonSafe = new GnosisSafe();
    GnosisSafeProxyFactory public safeFactory = new GnosisSafeProxyFactory();
    GnosisSafe public safe;
    HatsSignerGate public hatsSignerGate;
    address public constant HATS = address(0x4a15);
    bytes32 public constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    uint256 ownerHat;
    uint256 signerHat;
    uint256 targetThreshold;
    uint256 maxSigners;
    string public version;

    address[] public addresses;

    // error MaxSignersReached();

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

    // borrowed from Orca (https://github.com/orcaprotocol/contracts/blob/main/contracts/utils/SafeTxHelper.sol)
    function getSafeTxHash(
        address to,
        bytes memory data,
        GnosisSafe _safe
    ) public view returns (bytes32 txHash) {
        return
            _safe.getTransactionHash(
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

    function getEthTransferSafeTxHash(
        address to,
        uint256 value,
        GnosisSafe _safe
    ) public view returns (bytes32 txHash) {
        return
            _safe.getTransactionHash(
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

    // // modified from https://gist.github.com/sdelvalle57/f5f65a31150ea9321f081630b416ed99
    // function sort_array(bytes[] memory arr)
    //     internal
    //     pure
    //     returns (bytes[] memory)
    // {
    //     uint256 l = arr.length;
    //     for (uint256 i = 0; i < l; i++) {
    //         for (uint256 j = i + 1; j < l; j++) {
    //             if (arr[i] > arr[j]) {
    //                 bytes memory temp = arr[i];
    //                 arr[i] = arr[j];
    //                 arr[j] = temp;
    //             }
    //         }
    //     }
    //     return arr;
    // }

    function setUp() public virtual {
        // set up variables
        ownerHat = uint256(1);
        signerHat = uint256(2);
        targetThreshold = 2;
        maxSigners = 5;
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        version = "1.0";

        addresses = new address[](5);
        addresses[0] = vm.addr(100);
        addresses[1] = vm.addr(200);
        addresses[2] = vm.addr(300);
        addresses[3] = vm.addr(400);
        addresses[4] = vm.addr(500);

        // deploy safe
        safe = deploySafe(owners, 1);

        // deploy hats signer gate
        hatsSignerGate = new HatsSignerGate(
            ownerHat,
            signerHat,
            address(safe),
            HATS,
            targetThreshold,
            maxSigners,
            version
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
        executeSafeTxFrom(address(this), enableModuleData, safe);
        executeSafeTxFrom(address(this), setGuardData, safe);
    }
}
