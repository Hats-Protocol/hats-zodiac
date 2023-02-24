// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

// import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase, IGnosisSafe, Enum } from "./HatsSignerGateBase.sol";
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
            string memory _version,
            uint256 _existingModuleCount
        ) = abi.decode(
            initializeParams, (uint256, uint256[], address, address, uint256, uint256, uint256, string, uint256)
        );

        _setUp(_ownerHatId, _safe, _hats, _minThreshold, _targetThreshold, _maxSigners, _version, _existingModuleCount);

        _addSignerHats(_signerHats);
    }

    /// @notice Function to become an owner on the safe if you are wearing `_hatId` and `_hatId` is a valid signer hat
    /// @dev Reverts if `maxSigners` has been reached, the caller is either invalid or has already claimed. Swaps caller with existing invalid owner if relevant.
    /// @param _hatId The hat id to claim signer rights for
    function claimSigner(uint256 _hatId) public {
        uint256 maxSigs = maxSigners; // save SLOADs
        uint256 currentSignerCount = signerCount;

        if (currentSignerCount >= maxSigs) {
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

        /* 
        We check the safe owner count in case there are existing owners who are no longer valid signers. 
        If we're already at maxSigners, we'll replace one of the invalid owners by swapping the signer.
        Otherwise, we'll simply add the new signer.
        */
        address[] memory owners = safe.getOwners();
        uint256 ownerCount = owners.length;

        if (ownerCount >= maxSigs) {
            bool swapped = _swapSigner(owners, ownerCount, maxSigs, currentSignerCount, msg.sender);
            if (!swapped) {
                // if there are no invalid owners, we can't add a new signer, so we revert
                revert NoInvalidSignersToReplace();
            }
        } else {
            _grantSigner(owners, currentSignerCount, msg.sender);
        }

        // register the hat used to claim. This will be the hat checked in `checkTransaction()` for this signer
        claimedSignerHats[msg.sender] = _hatId;
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
    /// @param _hatId The hat id to check
    /// @return valid Whether `_hatId` is a valid signer hat
    function isValidSignerHat(uint256 _hatId) public view returns (bool valid) {
        valid = validSignerHats[_hatId];
    }
}
