// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase } from "./HatsSignerGateBase.sol";
import "./HSGLib.sol";

contract HatsSignerGate is HatsSignerGateBase {
    uint256 public signersHatId;

    /// @notice Initializes a new instance of HatsSignerGate
    /// @dev Can only be called once
    /// @param initializeParams ABI-encoded bytes with initialization parameters
    function setUp(bytes calldata initializeParams) public payable override initializer {
        (
            uint256 _ownerHatId,
            uint256 _signersHatId,
            address _safe,
            address _hats,
            uint256 _minThreshold,
            uint256 _targetThreshold,
            uint256 _maxSigners,
            string memory _version
        ) = abi.decode(initializeParams, (uint256, uint256, address, address, uint256, uint256, uint256, string));

        _setUp(_ownerHatId, _safe, _hats, _minThreshold, _targetThreshold, _maxSigners, _version);

        signersHatId = _signersHatId;
    }

    /// @notice Claims signer rights for `msg.sender` if `msg.sender` is a valid & new signer, updating the threshold if appropriate
    /// @dev Reverts if `maxSigners` has been reached
    function claimSigner() public virtual {
        // TODO TRST-H-4 - also remove invalid signers from the safe
        if (signerCount == maxSigners) {
            revert MaxSignersReached();
        }

        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }

        if (!isValidSigner(msg.sender)) {
            revert NotSignerHatWearer(msg.sender);
        }

        _grantSigner(msg.sender);
    }

    /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
    /// @dev Must be implemented by all flavors of HatsSignerGate
    /// @param _account The address to check
    /// @return valid Whether `_account` is a valid signer
    function isValidSigner(address _account) public view override returns (bool valid) {
        valid = HATS.isWearerOfHat(_account, signersHatId);
    }
}
