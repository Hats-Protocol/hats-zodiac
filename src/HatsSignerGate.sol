// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

// import {IHatsZodiac} from "../IHats.sol";
import "hats-auth/HatsOwned.sol";
import "zodiac/guard/BaseGuard.sol";
import "zodiac/interfaces/IAvatar.sol";
import "safe-contracts/common/StorageAccessible.sol";
import "./IGnosisSafe.sol";

contract HatsSignerGate is BaseGuard, HatsOwned {
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

    error FailedExecChangeThreshold();
    error FailedExecAddSigner();
    error FailedExecRemoveSigner();

    event TargetThresholdSet(uint256 threshold);

    address public avatar;
    uint256 public signersHatId;
    uint256 public targetThreshold;
    uint256 public immutable maxSigners;
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
        uint256 _ownerHatId, // TODO bring in HatsAuth
        uint256 _signersHatId,
        address _avatar, // Gnosis Safe that the signers will join
        address _hats,
        uint256 _targetThreshold,
        uint256 _maxSigners, // add 1 to the number of signers you really want
        string memory _version
    ) HatsOwned(_ownerHatId, _hats) {
        // bytes memory initializeParams = abi.encode(_ownerHatId, _avatar, _hats);
        // setUp(initializeParams);

        if (_maxSigners < 2) {
            revert NeedAtLeastTwoSigners();
        }

        avatar = _avatar;
        signersHatId = _signersHatId;
        targetThreshold = _targetThreshold;
        maxSigners = _maxSigners;
        version = _version;
    }

    // function setUp(bytes memory initializeParams) public override {
    //     // TODO enable factory support by overriding `setup`
    // }

    function setTargetThreshold(uint256 _targetThreshold) public onlyOwner {
        targetThreshold = _targetThreshold;

        // update the threshold in the Safe only if its lower than the current supply of the signer hat
        if (_targetThreshold <= HATS.hatSupply(signersHatId)) {
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
        if (!HATS.isWearerOfHat(_signer, signersHatId)) {
            revert NotSignerHatWearer(_signer);
        }

        // objective: 6 of 10 multisig
        // 0. multisig is created as 1 of 1 w/ module as the "signer"
        // 1. target threshold set at 6
        //    maxSigners set at 11
        //    1 of 1 multisig
        // 2. DAO mints 6 hats
        // 3. 1 person claims signer
        //    2 of 2 multisig
        // 4. 5 more people claim signer
        //    6 of 7 multisig
        // 5. DAO decides it doesn't want any more signers
        //    changes target threshold to 4
        //    4 of 7 multisig

        IGnosisSafe safe = IGnosisSafe(avatar);

        uint256 currentThreshold = safe.getThreshold();
        uint256 newThreshold = currentThreshold;
        uint256 newSignerCount = signerCount + 1;

        // ensure that txs can't execute if fewer signers than target threshold
        if (newSignerCount < targetThreshold) {
            newThreshold = newSignerCount;
        }

        // TODO may need to set threshold to 0 if signerCount < targetThreshold

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
        signerCount = newSignerCount;
    }

    function removeSigner(address _signer) public {
        if (HATS.isWearerOfHat(_signer, signersHatId)) {
            revert StillWearsSignerHat(_signer);
        }

        IGnosisSafe safe = IGnosisSafe(avatar);

        uint256 currentThreshold = safe.getThreshold();
        uint256 newThreshold = currentThreshold;
        uint256 newSignerCount = signerCount - 1;

        // ensure that txs can't execute if fewer signers than target threshold
        if (newSignerCount < targetThreshold) {
            newThreshold = newSignerCount;
        }

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
        signerCount = newSignerCount;
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
        // TODO revert if msg.sender is not a hat wearer

        IGnosisSafe safe = IGnosisSafe(avatar);

        // get the tx hash
        // fixme this is returning 0x for some reason??

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
            (v, r, s) = safe.signatureSplit(signatures, i);

            // fixme this is returning address(0) for some reason
            // likely has to do with the txHashData returning as 0x
            signer = ecrecover(txHash, v, r, s);

            // check if the signer is still valid, and increment the signature count if so
            if (HATS.isWearerOfHat(signer, signersHatId)) {
                ++validSigCount;
            }
        }

        // revert if there aren't enough valid signatures
        if (validSigCount < safe.getThreshold()) {
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
            revert CannotDisableProtectedModules(address(this));
        }
    }
}
