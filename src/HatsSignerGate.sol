// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import "hats-auth/HatsOwned.sol";
import "zodiac/guard/BaseGuard.sol";
import "zodiac/interfaces/IAvatar.sol";
import "@gnosis.pm/safe-contracts/contracts/common/StorageAccessible.sol";
import "./Interfaces/IGnosisSafe.sol";
import "forge-std/Test.sol"; // remove after testing
import "@gnosis.pm/safe-contracts/contracts/common/SignatureDecoder.sol";

contract HatsSignerGate is BaseGuard, SignatureDecoder, HatsOwned {
    // Cannot disable this guard
    error CannotDisableThisGuard(address guard);

    // Cannot disable protected modules
    error CannotDisableProtectedModules(address module);

    // Must wear the owner hat to make changes to this contract
    error NotOwnerHatWearer(address user);

    // Must wear the signer hat to become a signer
    error NotSignerHatWearer(address user);

    // Valid signers must wear the signer hat at time of execution
    error InvalidSigners();

    // Can't remove a signer if they're still wearing the signer hat
    error StillWearsSignerHat(address signer);

    // This module will always be a signer on the Safe
    error NeedAtLeastTwoSigners();

    error MaxSignersReached();

    // Target threshold must be lower than maxSigners
    error InvalidTargetThreshold();

    // Min threshold cannot be higher than maxSigners or targetThreshold
    error InvalidMinThreshold();

    error FailedExecChangeThreshold();
    error FailedExecAddSigner();
    error FailedExecRemoveSigner();

    // Cannot exec tx if safeOnwerCount < minThreshold
    error BelowMinThreshold(uint256 minThreshold, uint256 safeOwnerCount);

    event TargetThresholdSet(uint256 threshold);
    event MinThresholdSet(uint256 threshold);

    IGnosisSafe public safe;
    uint256 public signersHatId;
    uint256 public minThreshold;
    uint256 public targetThreshold;
    uint256 public immutable maxSigners;
    uint256 public signerCount;

    string public version;

    uint256 guardEntries;

    address internal constant SENTINEL_OWNERS = address(0x1);

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH =
        0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    constructor(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe, // Gnosis Safe that the signers will join
        address _hats,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners,
        string memory _version
    ) HatsOwned(_ownerHatId, _hats) {
        // bytes memory initializeParams = abi.encode(_ownerHatId, _avatar, _hats);
        // setUp(initializeParams);
        if (_maxSigners < 2) {
            revert NeedAtLeastTwoSigners();
        }

        maxSigners = _maxSigners;
        _setTargetThreshold(_targetThreshold);
        _setMinThreshold(_minThreshold);
        safe = IGnosisSafe(_safe);
        signersHatId = _signersHatId;
        version = _version;
        signerCount = 0;
    }

    // function setUp(bytes memory initializeParams) public override {
    //     // TODO enable factory support by overriding `setup`
    // }

    function setUp() public {
        // set HSG as a guard
        bytes memory setHSGGuard = abi.encodeWithSignature(
            "setGuard(address)",
            address(this)
        );

        bool success = safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            setHSGGuard, // data
            Enum.Operation.Call
        );
    }

    function setTargetThreshold(uint256 _targetThreshold) public onlyOwner {
        if (_targetThreshold != targetThreshold) {
            _setTargetThreshold(_targetThreshold);

            if (signerCount > 1) _setSafeThreshold(_targetThreshold);

            emit TargetThresholdSet(_targetThreshold);
        }
    }

    function _setTargetThreshold(uint256 _targetThreshold) internal {
        // (, uint32 maxSupply, , , , ) = HATS.viewHat(signersHatId);
        if (
            _targetThreshold > maxSigners
            // || _targetThreshold >= maxSupply
        ) revert InvalidTargetThreshold();

        targetThreshold = _targetThreshold;
    }

    function _setSafeThreshold(uint256 _targetThreshold) internal {
        uint256 newThreshold = _targetThreshold;
        uint256 signerCount_ = signerCount; // save an SLOAD

        // ensure that txs can't execute if fewer signers than target threshold
        if (signerCount_ <= _targetThreshold) {
            newThreshold = signerCount_;
            console2.log(newThreshold);
        }
        console2.log(safe.getThreshold());
        if (newThreshold != safe.getThreshold()) {
            bytes memory data = abi.encodeWithSelector(
                IGnosisSafe.changeThreshold.selector,
                newThreshold
            );

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

    function claimSigner() public {
        address signer = msg.sender;
        if (signerCount == maxSigners) {
            revert MaxSignersReached();
        }

        if (!HATS.isWearerOfHat(signer, signersHatId)) {
            revert NotSignerHatWearer(signer);
        }

        uint256 newSignerCount = signerCount;

        uint256 currentThreshold = safe.getThreshold();
        uint256 newThreshold = currentThreshold;

        bytes memory addOwnerData;
        address[] memory owners = safe.getOwners();
        address thisAddress = address(this);

        // console2.log("this", address(this));
        // console2.log("owners[0]", owners[0]);
        // console2.log("owners.length", owners.length);
        // console2.log("check", owners.length == 1 && owners[0] == thisAddress);

        if (owners.length == 1 && owners[0] == thisAddress) {
            // console2.log("if");
            address prevOwner = findPrevOwner(owners, thisAddress);

            addOwnerData = abi.encodeWithSelector(
                IGnosisSafe.swapOwner.selector,
                prevOwner, // prevOwner
                thisAddress, // oldOwner
                signer // newOwner
            );
            ++newSignerCount;
        } else {
            // console2.log("else");
            ++newSignerCount;

            // ensure that txs can't execute if fewer signers than target threshold
            if (newSignerCount <= targetThreshold) {
                newThreshold = newSignerCount;

                // console2.log("else if");
            }

            addOwnerData = abi.encodeWithSelector(
                IGnosisSafe.addOwnerWithThreshold.selector,
                signer,
                newThreshold
            );
        }

        bool success = safe.execTransactionFromModule(
            address(safe), // to
            0, // value
            addOwnerData, // data
            Enum.Operation.Call // operation
        );
        // console2.log("before last if");
        if (!success) {
            // console2.log("in last if");
            revert FailedExecAddSigner();
        }
        // increment signer count
        signerCount = newSignerCount;
    }

    function removeSigner(address _signer) public {
        if (HATS.isWearerOfHat(_signer, signersHatId)) {
            revert StillWearsSignerHat(_signer);
        }

        bytes memory removeOwnerData;
        address[] memory owners = safe.getOwners();
        address thisAddress = address(this);
        address prevOwner;

        uint256 currentThreshold = safe.getThreshold();
        uint256 newThreshold = currentThreshold;
        uint256 newSignerCount = signerCount;

        if (signerCount == 1) {
            prevOwner = findPrevOwner(owners, thisAddress);

            // make address(this) the only owner
            removeOwnerData = abi.encodeWithSelector(
                IGnosisSafe.swapOwner.selector,
                prevOwner, // prevOwner
                _signer, // oldOwner
                thisAddress // newOwner
            );
        } else {
            --newSignerCount;
            // ensure that txs can't execute if fewer signers than target threshold
            if (newSignerCount <= targetThreshold) {
                newThreshold = newSignerCount;
            }

            prevOwner = findPrevOwner(owners, _signer);

            removeOwnerData = abi.encodeWithSelector(
                IGnosisSafe.removeOwner.selector,
                prevOwner,
                _signer,
                newThreshold
            );

            // decrement signerCount
            signerCount = newSignerCount;
        }

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
    function findPrevOwner(address[] memory _owners, address owner)
        internal
        pure
        returns (address)
    {
        address prevOwner = SENTINEL_OWNERS;

        for (uint256 i = 0; i < _owners.length; ++i) {
            if (_owners[i] == owner) {
                if (i == 0) break;
                prevOwner = _owners[i - 1];
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
        address msgSender
    ) external override {
        uint256 safeOwnerCount = safe.getOwners().length;

        if (safeOwnerCount < minThreshold) {
            revert BelowMinThreshold(minThreshold, safeOwnerCount);
        }

        // get the tx hash
        bytes32 txHash = safe.getTransactionHash( // Transaction info
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
            safe.nonce() - 1
        );

        // signatures have length = 65
        uint256 sigCount = signatures.length / 65;

        uint8 v;
        bytes32 r;
        bytes32 s;
        address signer;
        uint256 validSigCount;

        // count up signers that are wearing the signer hat
        for (uint256 i = 0; i < sigCount; ++i) {
            // recover their address
            (v, r, s) = signatureSplit(signatures, i);

            signer = ecrecover(txHash, v, r, s);
            console2.log("recovered signer", signer);

            // check if the signer is still valid, and increment the signature count if so
            if (HATS.isWearerOfHat(signer, signersHatId)) {
                ++validSigCount;
            }
        }

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
            abi.decode(
                StorageAccessible(address(safe)).getStorageAt(
                    uint256(GUARD_STORAGE_SLOT),
                    1
                ),
                (address)
            ) != address(this)
        ) {
            revert CannotDisableThisGuard(address(this));
        }

        if (!IAvatar(address(safe)).isModuleEnabled(address(this))) {
            revert CannotDisableProtectedModules(address(this));
        }

        --guardEntries;
    }
}
