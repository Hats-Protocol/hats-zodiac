// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGFactoryTestSetup.t.sol";
import "../src/HSGLib.sol";
import "@gnosis.pm/safe-contracts/contracts/common/SignatureDecoder.sol";
import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

contract HSGTestSetup is HSGFactoryTestSetup {
    address public constant SENTINELS = address(0x1);

    uint256[] public pks;
    address[] public addresses;

    mapping(address => bytes) public walletSigs;

    uint256[] public signerHats;

    function setUp() public virtual {
        // set up variables
        ownerHat = 1;
        signerHats = new uint256[](5);
        signerHats[0] = 2;
        signerHats[1] = 3;
        signerHats[2] = 4;
        signerHats[3] = 5;
        signerHats[4] = 6;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        signerHat = signerHats[0];

        (pks, addresses) = createAddressesFromPks(10);

        version = "1.0";

        factory = new HatsSignerGateFactory(
            address(singletonHatsSignerGate),
            HATS,
            address(singletonSafe),
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            address(safeFactory),
            address(moduleProxyFactory),
            version
        );

        (hatsSignerGate, safe) = deployHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);
        mockIsWearerCall(address(hatsSignerGate), signerHat, false);

        mockIsWearerCall(address(hatsSignerGate), 0, false);
    }

    function addSignersOneHat(uint256 count, uint256 hat) internal {
        for (uint256 i = 0; i < count; i++) {
            mockIsWearerCall(addresses[i], hat, true);
            vm.prank(addresses[i]);
            hatsSignerGate.claimSigner(hat);
        }
    }

    function addSignersMultipleHats(uint256 count, uint256[] memory hats) internal {
        for (uint256 i = 0; i < count; i++) {
            mockIsWearerCall(addresses[i], hats[i], true);
            vm.prank(addresses[i]);
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
}
