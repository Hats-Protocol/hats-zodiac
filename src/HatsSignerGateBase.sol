// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import "./HSGErrors.sol";
import { HatsOwnedInitializable } from "hats-auth/HatsOwnedInitializable.sol";
import { BaseGuard } from "zodiac/guard/BaseGuard.sol";
import { IAvatar } from "zodiac/interfaces/IAvatar.sol";
import { StorageAccessible } from "@gnosis.pm/safe-contracts/contracts/common/StorageAccessible.sol";
import { IGnosisSafe, Enum } from "./Interfaces/IGnosisSafe.sol";
import { SignatureDecoder } from "@gnosis.pm/safe-contracts/contracts/common/SignatureDecoder.sol";

abstract contract HatsSignerGateBase is BaseGuard, SignatureDecoder, HatsOwnedInitializable {
    event TargetThresholdSet(uint256 threshold);
    event MinThresholdSet(uint256 threshold);

    IGnosisSafe public safe;

    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public maxSigners;
    uint256 public signerCount;

    string public version;

    uint256 internal guardEntries;

    address internal constant SENTINEL_OWNERS = address(0x1);

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @dev sets singleton owner to the 1 address, making it unusable
    constructor() initializer {
        _HatsOwned_init(1, address(0x1));
    }

    function setUp(bytes memory initializeParams) public virtual initializer { }

    function _setUp(
        uint256 _ownerHatId,
        address _safe,
        address _hats,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners,
        string memory _version
    ) internal {
        _HatsOwned_init(_ownerHatId, _hats);
        maxSigners = _maxSigners;
        safe = IGnosisSafe(_safe);

        _setTargetThreshold(_targetThreshold);
        _setMinThreshold(_minThreshold);
        version = _version;
    }

    /// @notice Checks if `_account` is a valid signer, ie is currently wearing the correct hat
    function isValidSigner(address _account) public view virtual returns (bool valid) { }

    function setTargetThreshold(uint256 _targetThreshold) public onlyOwner {
        if (_targetThreshold != targetThreshold) {
            _setTargetThreshold(_targetThreshold);

            if (signerCount > 1) _setSafeThreshold(_targetThreshold);

            emit TargetThresholdSet(_targetThreshold);
        }
    }

    function _setTargetThreshold(uint256 _targetThreshold) internal {
        if (_targetThreshold > maxSigners) {
            revert InvalidTargetThreshold();
        }

        targetThreshold = _targetThreshold;
    }

    function _setSafeThreshold(uint256 _targetThreshold) internal {
        uint256 newThreshold = _targetThreshold;
        uint256 signerCount_ = signerCount; // save an SLOAD

        // ensure that txs can't execute if fewer signers than target threshold
        if (signerCount_ <= _targetThreshold) {
            newThreshold = signerCount_;
        }
        if (newThreshold != safe.getThreshold()) {
            bytes memory data = abi.encodeWithSelector(IGnosisSafe.changeThreshold.selector, newThreshold);

            bool success = safe.execTransactionFromModule(
                address(safe), // to
                0, // value
                data, // data
                Enum.Operation.Call // operation
            );

            if (!success) {
                revert FailedExecChangeThreshold();
            }
        }
    }

    function setMinThreshold(uint256 _minThreshold) public onlyOwner {
        _setMinThreshold(_minThreshold);
        emit MinThresholdSet(_minThreshold);
    }

    function _setMinThreshold(uint256 _minThreshold) internal {
        if (_minThreshold > maxSigners || _minThreshold > targetThreshold) {
            revert InvalidMinThreshold();
        }

        minThreshold = _minThreshold;
    }

    /// @notice tallies the number of existing safe owners that wear the signer hat, sets signerCount to that value, and updates the safe threshold if necessary
    /// @dev does NOT remove invalid safe owners
    function reconcileSignerCount() public {
        address[] memory owners = safe.getOwners();
        uint256 validSignerCount = _countValidSigners(owners);

        // update the signer count accordingly
        signerCount = validSignerCount;

        if (validSignerCount <= targetThreshold && validSignerCount != safe.getThreshold()) {
            bytes memory data = abi.encodeWithSelector(IGnosisSafe.changeThreshold.selector, validSignerCount);

            bool success = safe.execTransactionFromModule(
                address(safe), // to
                0, // value
                data, // data
                Enum.Operation.Call // operation
            );

            if (!success) {
                revert FailedExecChangeThreshold();
            }
        }
    }

    function _countValidSigners(address[] memory owners) internal view returns (uint256 validSignerCount) {
        // count the existing safe owners that wear the signer hat
        for (uint256 i = 0; i < owners.length;) {
            if (isValidSigner(owners[i])) {
                // shouldn't overflow given reasonable owners array length
                unchecked {
                    ++validSignerCount;
                }
            }
            // shouldn't overflow given reasonable owners array length
            unchecked {
                ++i;
            }
        }
    }

    function claimSigner() public virtual {
        if (signerCount == maxSigners) {
            revert MaxSignersReached();
        }

        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }

        if (!isValidSigner(msg.sender)) {
            revert NotSignerHatWearer(msg.sender);
        }

        _claimSigner(msg.sender);
    }

    function _claimSigner(address claimer) internal {
        uint256 newSignerCount = signerCount;

        uint256 currentThreshold = safe.getThreshold(); // view function
        uint256 newThreshold = currentThreshold;

        bytes memory addOwnerData;
        address[] memory owners = safe.getOwners(); // view function
        address thisAddress = address(this);

        // if the only owner is a non-signer (ie this module set as an owner on initialization), replace it with the claimer
        if (owners.length == 1 && owners[0] == thisAddress) {
            // prevOwner will always be the sentinel when owners.length == 1

            // set up the swapOwner call
            // TODO replace with encodeWithSignature, which is slightly cheaper
            addOwnerData = abi.encodeWithSelector(
                IGnosisSafe.swapOwner.selector,
                SENTINEL_OWNERS, // prevOwner
                thisAddress, // oldOwner
                claimer // newOwner
            );
            unchecked {
                // shouldn't overflow given MaxSignersReached check higher in call stack
                ++newSignerCount;
            }
        } else {
            // otherwise, add the claimer as a new owner

            unchecked {
                // shouldn't overflow given MaxSignersReached check higher in call stack
                ++newSignerCount;
            }

            // ensure that txs can't execute if fewer signers than target threshold
            if (newSignerCount <= targetThreshold) {
                newThreshold = newSignerCount;
            }

            // set up the addOwner call
            // TODO replace with encodeWithSignature, which is slightly cheaper
            addOwnerData = abi.encodeWithSelector(IGnosisSafe.addOwnerWithThreshold.selector, claimer, newThreshold);
        }

        // increment signer count
        signerCount = newSignerCount;

        // execute the call
        bool success = safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnerData, // data
            Enum.Operation.Call // operation
        );

        if (!success) {
            revert FailedExecAddSigner();
        }
    }

    function removeSigner(address _signer) public virtual {
        if (isValidSigner(_signer)) {
            revert StillWearsSignerHat(_signer);
        }

        _removeSigner(_signer);
    }

    function _removeSigner(address _signer) internal {
        bytes memory removeOwnerData;
        address[] memory owners = safe.getOwners();
        address thisAddress = address(this);
        uint256 currentSignerCount = signerCount; // save an SLOAD
        uint256 newSignerCount;

        if (currentSignerCount < 2 && owners.length == 1) {
            // signerCount could be 0 after reconcileSignerCount
            // make address(this) the only owner
            removeOwnerData = abi.encodeWithSelector(
                IGnosisSafe.swapOwner.selector,
                SENTINEL_OWNERS, // prevOwner
                _signer, // oldOwner
                thisAddress // newOwner
            );

            // newSignerCount is already 0
        } else {
            uint256 currentThreshold = safe.getThreshold();
            uint256 newThreshold = currentThreshold;
            uint256 validSignerCount = _countValidSigners(owners);

            if (validSignerCount == currentSignerCount) {
                newSignerCount = currentSignerCount;
            } else {
                newSignerCount = currentSignerCount - 1;
            }

            // ensure that txs can't execute if fewer signers than target threshold
            if (newSignerCount <= targetThreshold) {
                newThreshold = newSignerCount;
            }

            removeOwnerData = abi.encodeWithSelector(
                IGnosisSafe.removeOwner.selector, findPrevOwner(owners, _signer), _signer, newThreshold
            );
        }

        // update signerCount
        signerCount = newSignerCount;

        bool success = safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            removeOwnerData, // data
            Enum.Operation.Call // operation
        );

        if (!success) {
            revert FailedExecRemoveSigner();
        }
    }

    // find the previous owner, ie the pointer to the owner we want to remove from the safe owners linked list
    function findPrevOwner(address[] memory _owners, address owner) internal pure returns (address) {
        address prevOwner = SENTINEL_OWNERS;

        for (uint256 i = 0; i < _owners.length;) {
            if (_owners[i] == owner) {
                if (i == 0) break;
                prevOwner = _owners[i - 1];
            }
            // shouldn't overflow given reasonable _owners array length
            unchecked {
                ++i;
            }
        }

        return prevOwner;
    }

    // solhint-disallow-next-line payable-fallback
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    // pre-flight check
    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address // msgSender
    ) external override {
        uint256 safeOwnerCount = safe.getOwners().length;

        if (safeOwnerCount < minThreshold) {
            revert BelowMinThreshold(minThreshold, safeOwnerCount);
        }

        // get the tx hash; view function
        bytes32 txHash = safe.getTransactionHash(
            // Transaction info
            to,
            value,
            data,
            operation,
            safeTxGas,
            // Payment info
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            // Signature info
            // We subtract 1 since nonce was just incremented in the parent function call
            safe.nonce() - 1 // view function
        );

        uint256 validSigCount = countValidSignatures(txHash, signatures, signatures.length / 65);

        // revert if there aren't enough valid signatures
        if (validSigCount < safe.getThreshold()) {
            revert InvalidSigners();
        }

        ++guardEntries;
    }

    /// @notice from https://github.com/gnosis/zodiac-guard-mod/blob/988ebc7b71e352f121a0be5f6ae37e79e47a4541/contracts/ModGuard.sol#L86
    /// @dev Prevent avatar owners (eg Safe signers) to remove this contract as a guard or as a module
    // TODO check on safety changes to above
    function checkAfterExecution(bytes32, bool) external override {
        if (
            abi.decode(StorageAccessible(address(safe)).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address))
                != address(this)
        ) {
            revert CannotDisableThisGuard(address(this));
        }

        if (!IAvatar(address(safe)).isModuleEnabled(address(this))) {
            revert CannotDisableProtectedModules(address(this));
        }

        --guardEntries;
    }

    // modified from https://github.com/safe-global/safe-contracts/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/GnosisSafe.sol#L240
    function countValidSignatures(bytes32 dataHash, bytes memory signatures, uint256 sigCount)
        public
        view
        returns (uint256 validSigCount)
    {
        // There cannot be an owner with address 0.
        address currentOwner;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 i;

        for (i = 0; i < sigCount;) {
            (v, r, s) = signatureSplit(signatures, i);
            if (v == 0) {
                // If v is 0 then it is a contract signature
                // When handling contract signatures the address of the contract is encoded into r
                currentOwner = address(uint160(uint256(r)));
            } else if (v == 1) {
                // If v is 1 then it is an approved hash
                // When handling approved hashes the address of the approver is encoded into r
                currentOwner = address(uint160(uint256(r)));
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the Ethereum message prefix before applying ecrecover
                currentOwner =
                    ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash)), v - 4, r, s);
            } else {
                // Default is the ecrecover flow with the provided data hash
                // Use ecrecover with the messageHash for EOA signatures
                currentOwner = ecrecover(dataHash, v, r, s);
            }

            if (isValidSigner(currentOwner)) {
                // shouldn't overflow given reasonable sigCount
                unchecked {
                    ++validSigCount;
                }
            }
            // shouldn't overflow given reasonable sigCount
            unchecked {
                ++i;
            }
        }
    }
}
