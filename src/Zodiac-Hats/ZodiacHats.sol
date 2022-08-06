// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import "../IHats.sol";
import "zodiac/core/Module.sol";
import "zodiac/guard/BaseGuard.sol";

contract ZodiacHats is Module, BaseGuard {
    // Cannot disable this guard
    error CannotDisableThisGuard(address guard);

    // Cannot disable protected modules
    error CannotDisableProtecedModules(address module);

    // Must wearer the owner hat
    error NotOwnerHatWearer(address user, uint256 ownerHatId);

    event AvatarSet(address avatar);

    address public immutable HATS;
    uint256 public immutable ownerHatId;

    // keccak256("guard_manager.guard.address")
    bytes32 internal constant GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    constructor(
        uint256 _ownerHatId,
        address _avatar,
        address _hats
    ) {
        // bytes memory initializeParams = abi.encode(_ownerHatId, _avatar, _hats);
        // setUp(initializeParams);
        avatar = _avatar;
        HATS = _hats;
        ownerHatId = _ownerHatId;

        // TODO enable factory support by overriding `setup`
    }

    function setAvatar(address _avatar) public onlyOwnerHatWearer {
        avatar = _avatar;
        emit AvatarSet(avatar);
    }

    // solhint-disallow-next-line payable-fallback
    fallback() external {
        // We don't revert on fallback to avoid issues in case of a Safe upgrade
        // E.g. The expected check method might change and then the Safe would be locked.
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external override {
        //
    }

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

    modifier onlyOwnerHatWearer() {
        if (!HATS.isWearerOfHat(msg.sender, ownerHatId)) {
            revert NotOwnerHatWearer(msg.sender, ownerHatId);
        }
        _;
    }
}
