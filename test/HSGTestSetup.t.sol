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
    address public SENTINELS = address(0x1);
    uint256 ownerHat;
    uint256 signerHat;
    uint256 minThreshold;
    uint256 targetThreshold;
    uint256 maxSigners;
    string public version;

    uint256[] public pks;
    address[] public addresses;

    mapping(address => bytes) public walletSigs;

    //// SETUP FUNCTION ////

    function setUp() public virtual {
        // set up variables
        ownerHat = uint256(1);
        signerHat = uint256(2);
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;
        address[] memory initSafeOwners = new address[](1);
        initSafeOwners[0] = address(this);
        version = "1.0";

        (pks, addresses) = createAddressesFromPks(5);

        // deploy safe
        safe = deploySafe(initSafeOwners, 1);

        // deploy hats signer gate
        hatsSignerGate = new HatsSignerGate(
            ownerHat,
            signerHat,
            address(safe),
            HATS,
            minThreshold,
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

    //// HELPER FUNCTIONS ////

    function addSigners(uint256 signerCount) public {
        for (uint256 i = 0; i < signerCount; ++i) {
            // mock mint the signerHat
            mockIsWearerCall(addresses[i], signerHat, true);

            // add as signer
            vm.prank(addresses[i]);
            hatsSignerGate.claimSigner();
        }
    }

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

    function getTxHash(
        address to,
        uint256 value,
        bytes memory data,
        GnosisSafe _safe
    ) public view returns (bytes32 txHash) {
        return
            _safe.getTransactionHash(
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

    function createNSigsForTx(
        bytes32 txHash,
        uint256 signerCount,
        GnosisSafe _safe
    ) public returns (bytes memory signatures) {
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
            emit log_address(addy);
            signatures = bytes.concat(signatures, walletSigs[addy]);
        }
    }

    function signaturesForEthTransferTx(
        address to,
        uint256 value,
        uint256 signerCount,
        GnosisSafe _safe
    ) public returns (bytes memory signatures) {
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
            emit log_address(addy);
            signatures = bytes.concat(signatures, walletSigs[addy]);
        }
    }

    function createAddressesFromPks(uint256 count)
        public
        returns (uint256[] memory pks_, address[] memory addresses_)
    {
        pks_ = new uint256[](count);
        addresses_ = new address[](count);

        for (uint256 i = 0; i < count; ++i) {
            pks_[i] = 100 * (i + 1);
            addresses_[i] = vm.addr(pks_[i]);
        }
    }

    // borrowed from https://gist.github.com/subhodi/b3b86cc13ad2636420963e692a4d896f
    function sort(
        uint256[] memory arr,
        int256 left,
        int256 right
    ) internal {
        int256 i = left;
        int256 j = right;
        if (i == j) return;
        uint256 pivot = arr[uint256(left + (right - left) / 2)];
        while (i <= j) {
            while (arr[uint256(i)] < pivot) i++;
            while (pivot < arr[uint256(j)]) j--;
            if (i <= j) {
                (arr[uint256(i)], arr[uint256(j)]) = (
                    arr[uint256(j)],
                    arr[uint256(i)]
                );
                i++;
                j--;
            }
        }
        if (left < j) sort(arr, left, j);
        if (i < right) sort(arr, i, right);
    }
}
