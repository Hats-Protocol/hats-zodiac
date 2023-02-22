// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase } from "./HatsSignerGateBase.sol";
import "./HSGLib.sol";

contract MultiHatsSignerGate is HatsSignerGateBase {
    /// @notice Append-only tracker of approved signer hats
    mapping(uint256 => bool) public validSignerHats;

    /// @notice Tracks the hat ids worn by users who have "claimed signer"
    mapping(address => uint256) public claimedSignerHats;

    /// @notice Initializes a new instance of MultiHatsSignerGate
    /// @dev Can only be called once
    /// @param initializeParams ABI-encoded bytes with initialization parameters
    function setUp(bytes calldata initializeParams) public payable override initializer {
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

    /// @notice Function to become an owner on the safe if you are wearing `_hatId` and `_hatId` is a valid signer hat
    function claimSigner(uint256 _hatId) public {
        if (signerCount >= maxSigners) {
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

        // register the hat used to claim. This will be the hat checked in `checkTransaction() for this signer`
        claimedSignerHats[msg.sender] = _hatId;

        _grantSigner(msg.sender);
    }

    /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
    /// @dev Must be implemented by all flavors of HatsSignerGate
    /// @param _account The address to check
    /// @return valid Whether `_account` is a valid signer
    function isValidSigner(address _account) public view override returns (bool valid) {
        /// @dev existing `claimedSignerHats` are always valid, since `validSignerHats` is append-only
        valid = HATS.isWearerOfHat(_account, claimedSignerHats[_account]);
    }

    /// @notice Adds new approved signer hats
    /// @param _newSignerHats Array of hat ids to add as approved signer hats
    function addSignerHats(uint256[] calldata _newSignerHats) external onlyOwner {
        _addSignerHats(_newSignerHats);

        emit HSGLib.SignerHatsAdded(_newSignerHats);
    }

    /// @notice Internal function to approve new signer hats
    /// @param _newSignerHats Array of hat ids to add as approved signer hats
    function _addSignerHats(uint256[] memory _newSignerHats) internal {
        for (uint256 i = 0; i < _newSignerHats.length;) {
            validSignerHats[_newSignerHats[i]] = true;

            // should not overflow with feasible array length
            unchecked {
                ++i;
            }
        }
    }

    /// @notice A `_hatId` is valid if it is included in the `validSignerHats` mapping
    function isValidSignerHat(uint256 _hatId) public view returns (bool valid) {
        valid = validSignerHats[_hatId];
    }
}
