// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase } from "./HatsSignerGateBase.sol";
import "./HSGErrors.sol";

contract MultiHatsSignerGate is HatsSignerGateBase {
    event AddSignerHats(uint256[] newSignerHats);

    /// @notice Tracks approved signer hats
    /// @dev append only
    mapping(uint256 => bool) public validSignerHats;

    /// @notice Tracks the hat ids worn by users who have "claimed signer"
    mapping(address => uint256) public claimedSignerHats;

    /// @notice A `_hatId` is valid if it is included in the `validSignerHats` mapping
    function isValidSignerHat(uint256 _hatId) public view returns (bool valid) {
        valid = validSignerHats[_hatId];
    }

    function isValidSigner(address _account) public view override returns (bool valid) {
        /// @dev existing `claimedSignerHats` are always valid, since `validSignerHats` is append-only
        valid = HATS.isWearerOfHat(_account, claimedSignerHats[_account]);
    }

    function setUp(bytes memory initializeParams) public override initializer {
        (
            uint256 _ownerHatId,
            uint256[] memory _signerHats,
            address _safe,
            address _hats,
            uint256 _minThreshold,
            uint256 _targetThreshold,
            uint256 _maxSigners,
            string memory _version
        ) = abi.decode(initializeParams, (uint256, uint256[], address, address, uint256, uint256, uint256, string));

        _setUp(_ownerHatId, _safe, _hats, _minThreshold, _targetThreshold, _maxSigners, _version);

        _addSignerHats(_signerHats);
    }

    function _addSignerHats(uint256[] memory _newSignerHats) internal {
        for (uint256 i = 0; i < _newSignerHats.length;) {
            validSignerHats[_newSignerHats[i]] = true;

            // should not overflow with feasible array length
            unchecked {
                ++i;
            }
        }
    }

    function addSignerHats(uint256[] memory _newSignerHats) external onlyOwner {
        _addSignerHats(_newSignerHats);
        emit AddSignerHats(_newSignerHats);
    }

    /// @notice Function to become an owner on the safe if you are wearing `_hatId` and `_hatId` is a valid signer hat
    /// @dev overloads HatsSignerGateBase.claimSigner()
    function claimSigner(uint256 _hatId) public {
        if (signerCount == maxSigners) {
            revert MaxSignersReached();
        }

        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }

        if (!isValidSignerHat(_hatId)) {
            revert InvalidSignerHat(_hatId);
        }

        if (!HATS.isWearerOfHat(msg.sender, _hatId)) {
            revert NotSignerHatWearer(msg.sender);
        }

        _claimSigner(msg.sender);
    }
}
