// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

// import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase, IGnosisSafe, Enum } from "./HatsSignerGateBase.sol";
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
        uint256 maxSigs = maxSigners; // save SLOADs
        uint256 currentSignerCount = signerCount;

        if (currentSignerCount >= maxSigs) {
            revert MaxSignersReached();
        }

        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }

        if (!isValidSigner(msg.sender)) {
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
            _swapSigner(owners, ownerCount, maxSigs, currentSignerCount, msg.sender);
        } else {
            _grantSigner(owners, currentSignerCount, msg.sender);
        }
    }

    /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
    /// @dev Must be implemented by all flavors of HatsSignerGate
    /// @param _account The address to check
    /// @return valid Whether `_account` is a valid signer
    function isValidSigner(address _account) public view override returns (bool valid) {
        valid = HATS.isWearerOfHat(_account, signersHatId);
    }
}
