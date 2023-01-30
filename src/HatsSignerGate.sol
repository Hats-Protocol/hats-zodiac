// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase } from "./HatsSignerGateBase.sol";
import "./HSGErrors.sol";

contract HatsSignerGate is HatsSignerGateBase {
    uint256 public signersHatId;

    function setUp(bytes memory initializeParams) public override initializer {
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

    function isValidSigner(address _account) public view override returns (bool valid) {
        valid = HATS.isWearerOfHat(_account, signersHatId);
    }
}
