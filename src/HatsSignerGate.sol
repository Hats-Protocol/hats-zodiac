// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { Test, console2 } from "forge-std/Test.sol"; // comment out after testing
import { HatsSignerGateBase, ISafe } from "./HatsSignerGateBase.sol";
import { SafeDeployer } from "./SafeDeployer.sol";
import "./HSGLib.sol";

contract HatsSignerGate is HatsSignerGateBase, SafeDeployer {
    /// @notice Append-only tracker of approved signer hats
    mapping(uint256 => bool) public validSignerHats;

    /// @notice Tracks the hat ids worn by users who have "claimed signer"
    mapping(address => uint256) public claimedSignerHats;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _safeSingleton,
        address _safeFallbackLibrary,
        address _safeMultisendLibrary,
        address _safeProxyFactory
    ) SafeDeployer(_safeSingleton, _safeFallbackLibrary, _safeMultisendLibrary, _safeProxyFactory) { }

    /*//////////////////////////////////////////////////////////////
                              INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initializes a new instance of MultiHatsSignerGate
     * @dev Can only be called once
     * @param initializeParams ABI-encoded bytes with initialization parameters
     * @custom:field _ownerHatId The id of the owner hat
     * @custom:field _signerHats The ids of the signer hats
     * @custom:field _safe The address of the existing safe, or zero address to deploy a new safe
     * @custom:field _hats The address of the Hats Protocol contract
     * @custom:field _minThreshold The minimum signature threshold
     * @custom:field _targetThreshold The target signature threshold
     * @custom:field _maxSigners The maximum number of signers
     * @custom:field _version The version of the contract
     */
    function setUp(bytes calldata initializeParams) public payable initializer {
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

        bool emptySafe = _safe == address(0);

        if (emptySafe) {
            _safe = _deploySafeAndAttachHSG();
        }

        _setUpHSG(_ownerHatId, _safe, _hats, _minThreshold, _targetThreshold, _maxSigners, _version);

        _addSignerHats(_signerHats);

        // TODO optimize this so that we don't have to do another if statement here
        if (!emptySafe) {
            if (!_canAttachToSafe(ISafe(_safe))) revert CannotAttachToSafe();
        }
    }

    /*//////////////////////////////////////////////////////////////
                              PUBLIC FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Function to become an owner on the safe if you are wearing `_hatId` and `_hatId` is a valid signer hat
    /// @dev Reverts if `maxSigners` has been reached, the caller is either invalid or has already claimed. Swaps caller with existing invalid owner if relevant.
    /// @param _hatId The hat id to claim signer rights for
    function claimSigner(uint256 _hatId) public {
        uint256 maxSigs = maxSigners; // save SLOADs
        address[] memory owners = safe.getOwners();

        uint256 currentSignerCount = _countValidSigners(owners);

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
        uint256 ownerCount = owners.length;

        if (ownerCount >= maxSigs) {
            bool swapped = _swapSigner(owners, ownerCount, msg.sender);
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

    /**
     * @notice Checks if a HatsSignerGate can be safely attached to a Safe
     * @dev There must be...
     *      1) No existing modules on the Safe
     *      2) HatsSignerGate's `validSignerCount()` must be <= `_maxSigners`
     */
    function _canAttachToSafe(ISafe _safe) internal view returns (bool) {
        (address[] memory modulesWith1,) = _safe.getModulesPaginated(SENTINELS, 1);

        return (modulesWith1.length == 0);

        // QUESTION: do we need to bring back the valid signer count <= maxSigners check?
        // return (modulesWith1.length == 0 && _countValidSigners(_safe.getOwners()) <= maxSigners);
    }

    /**
     * @notice Checks if a HatsSignerGate can be safely attached to a Safe
     * @dev There must be...
     *      1) No existing modules on the Safe
     *      2) HatsSignerGate's `validSignerCount()` must be <= `_maxSigners`
     */
    function canAttachToSafe() public view returns (bool) {
        return _canAttachToSafe(safe);
    }
}
