// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGFactoryTestSetup.t.sol";
import "./HatsSignerGateFactory.t.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

contract HSGTestSetup is HSGFactoryTestSetup {
    address public SENTINELS = address(0x1);

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

        // initSafeOwners[0] = address(this);

        (pks, addresses) = createAddressesFromPks(5);

        // // deploy safe
        // safe = deploySafe(initSafeOwners, 1);

        // // deploy hats signer gate
        // hatsSignerGate = new HatsSignerGate(
        //     ownerHat,
        //     signerHat,
        //     address(safe),
        //     HATS,
        //     minThreshold,
        //     targetThreshold,
        //     maxSigners,
        //     version
        // );

        // // add hats signer gate as module and guard
        // // encode txs
        // bytes memory enableModuleData = abi.encodeWithSignature(
        //     "enableModule(address)",
        //     address(hatsSignerGate)
        // );

        // bytes memory setGuardData = abi.encodeWithSignature(
        //     "setGuard(address)",
        //     address(hatsSignerGate)
        // );

        // // execute txs
        // executeSafeTxFrom(address(this), enableModuleData, safe);
        // executeSafeTxFrom(address(this), setGuardData, safe);
        version = "1.0";

        factory = new HatsSignerGateFactory(
            HATS,
            address(singletonSafe),
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            address(safeFactory),
            version
        );

        (hatsSignerGate, safe) = deployHSGAndSafe(
            ownerHat,
            signerHat,
            minThreshold,
            targetThreshold,
            maxSigners
        );
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
