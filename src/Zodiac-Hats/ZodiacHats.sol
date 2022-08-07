// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import "../IHats.sol";
import "zodiac/core/Module.sol";
import "zodiac/guard/BaseGuard.sol";
import "zodiac/interfaces/IAvatar.sol";
import "safe-contracts/common/SignatureDecoder.sol";
import "safe-contracts/common/StorageAccessible.sol";
import "./IGnosisSafe.sol";

contract ZodiacHats is Module, BaseGuard, SignatureDecoder {
    // Cannot disable this guard
    error CannotDisableThisGuard(address guard);

    // Cannot disable protected modules
    error CannotDisableProtecedModules(address module);

    // Must wear the owner hat to make changes to this contract
    error NotOwnerHatWearer(address user);

    // Must wear the signer hat to become a signer
    error NotSignerHatWearer(address user);

    // Valid signers must wear the signer hat at time of execution
    error InvalidSigners();

    // Can't remove a signer if they're still wearing the signer hat
    error StillWearsSignerHat(address signer);

    error FailedExecChangeThreshold();
    error FailedExecAddSigner();
    error FailedExecRemoveSigner();

    event AvatarSet(address avatar);
    event TargetThresholdSet(uint256 threshold);

    IHats public immutable hats;
    uint256 public immutable ownerHatId;
    uint256 public signersHatId;
    uint256 public targetThreshold;
    uint256 public signerCount;

    string public version;

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
        address _avatar,
        address _hats,
        uint8 _targetThreshold,
        string memory _version
    ) {
        // bytes memory initializeParams = abi.encode(_ownerHatId, _avatar, _hats);
        // setUp(initializeParams);
        avatar = _avatar;
        hats = IHats(_hats);
        ownerHatId = _ownerHatId;
        signersHatId = _signersHatId;
        targetThreshold = _targetThreshold;
        version = _version;
    }

    function setUp(bytes memory initializeParams) public override {
        // TODO enable factory support by overriding `setup`
    }

    function setTargetThreshold(uint256 _targetThreshold) public onlyOwner {
        targetThreshold = _targetThreshold;

        // update the threshold in the Safe only if its lower than the current supply of the signer hat
        if (_targetThreshold < hats.hatSupply(signersHatId)) {
            bytes memory data = abi.encodeWithSignature(
                "changeThreshold(uint256)",
                _targetThreshold
            );

            bool success = IGnosisSafe(avatar).execTransactionFromModule(
                avatar, // to
                0, // value
                data, // data
                Enum.Operation.Call // operation
            );

            if (!success) {
                revert FailedExecChangeThreshold();
            }
        }

        emit TargetThresholdSet(_targetThreshold);
    }

    function claimSigner() external {
        addSigner(msg.sender);
    }

    function addSigner(address _signer) public {
        if (!hats.isWearerOfHat(_signer, signersHatId)) {
            revert NotSignerHatWearer(msg.sender);
        }

        IGnosisSafe safe = IGnosisSafe(avatar);

        uint256 currentThreshold = safe.getThreshold();
        uint256 newThreshold = currentThreshold;

        // ensure that safe.threshold >= # of signers
        if (signerCount < targetThreshold) {
            newThreshold = signerCount + 1;
        }

        bytes memory data = abi.encodeWithSignature(
            "addOwnerWithThreshold(address,uint256)",
            _signer,
            newThreshold
        );

        bool success = safe.execTransactionFromModule(
            avatar, // to
            0, // value
            data, // data
            Enum.Operation.Call // operation
        );

        if (!success) {
            revert FailedExecAddSigner();
        }

        // increment signer count
        ++signerCount;
    }

    function removeSigner(address _signer) public {
        if (hats.isWearerOfHat(msg.sender, signersHatId)) {
            revert StillWearsSignerHat(msg.sender);
        }

        IGnosisSafe safe = IGnosisSafe(avatar);

        address[] memory owners = safe.getOwners();
        address prevOwner = SENTINEL_OWNERS;

        // find the previous owner, ie the pointer to the owner we want to remove from the safe owners linked list
        for (uint256 i = 0; i < owners.length; ++i) {
            if (owners[i] == _signer) {
                if (i == 0) break;
                prevOwner = owners[i - 1];
            }
        }

        bytes memory data = abi.encodeWithSignature(
            "removeOwner(address,address,uint256)",
            prevOwner,
            _signer,
            safe.getThreshold()
        );

        bool success = safe.execTransactionFromModule(
            avatar, // to
            0, // value
            data, // data
            Enum.Operation.Call // operation
        );

        if (!success) {
            revert FailedExecRemoveSigner();
        }

        // decrement signer count
        --signerCount;
    }

    // solhint-disallow-next-line payable-fallback
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    /// @notice from https://github.com/safe-global/safe-contracts/blob/c36bcab46578a442862d043e12a83fec41143dec/contracts/GnosisSafe.sol#L353
    /// @dev Returns the bytes that are hashed to be signed by owners.
    /// @param to Destination address.
    /// @param value Ether value.
    /// @param data Data payload.
    /// @param operation Operation type.
    /// @param safeTxGas Gas that should be used for the safe transaction.
    /// @param baseGas Gas costs for that are independent of the transaction execution(e.g. base transaction fee, signature check, payment of the refund)
    /// @param gasPrice Maximum gas price that should be used for this transaction.
    /// @param gasToken Token address (or 0 if ETH) that is used for the payment.
    /// @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
    /// @param _nonce Transaction nonce.
    /// @return Transaction hash bytes.
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) public view returns (bytes memory) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return
            abi.encodePacked(
                bytes1(0x19),
                bytes1(0x01),
                IGnosisSafe(avatar).domainSeparator(),
                safeTxHash
            );
    }

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
        // get the tx hash
        // fixme this is returning 0x for some reason
        bytes memory txHashData = encodeTransactionData(
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
            IGnosisSafe(avatar).nonce() - 1
        );

        bytes32 txHash = keccak256(txHashData);

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

            // fixme this is returning address(0) for some reason
            // likely has to do with the txHashData returning as 0x
            signer = ecrecover(txHash, v, r, s);

            // check if the signer is still valid, and increment the signature count if so
            if (hats.isWearerOfHat(signer, signersHatId)) {
                ++validSigCount;
            }
        }

        // revert if there aren't enough valid signatures
        if (validSigCount < IGnosisSafe(avatar).getThreshold()) {
            revert InvalidSigners();
        }
    }

    /// @notice from https://github.com/gnosis/zodiac-guard-mod/blob/988ebc7b71e352f121a0be5f6ae37e79e47a4541/contracts/ModGuard.sol#L86
    /// @dev Prevent avatar owners (eg Safe signers) to remove this contract as a guard or as a module
    function checkAfterExecution(bytes32, bool) external view override {
        if (
            abi.decode(
                StorageAccessible(avatar).getStorageAt(
                    uint256(GUARD_STORAGE_SLOT),
                    2
                ),
                (address)
            ) != address(this)
        ) {
            revert CannotDisableThisGuard(address(this));
        }

        if (!IAvatar(avatar).isModuleEnabled(address(this))) {
            revert CannotDisableProtecedModules(address(this));
        }
    }

    function _checkOwner() internal view override {
        if (!hats.isWearerOfHat(msg.sender, ownerHatId)) {
            revert NotOwnerHatWearer(msg.sender);
        }
    }
}
