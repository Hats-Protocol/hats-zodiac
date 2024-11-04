// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, ISafe, TestSuite, WithHSGHarnessInstanceTest, HatsSignerGate } from "./TestSuite.t.sol";
import { IHats, IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { DeployInstance } from "../script/HatsSignerGate.s.sol";
import { IAvatar } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { IModuleManager } from "../src/lib/safe-interfaces/IModuleManager.sol";
import { GuardableUnowned } from "../src/lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { TestGuard } from "./mocks/TestGuard.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";

contract AuthInternals is WithHSGHarnessInstanceTest {
  function test_happy_checkOwner() public {
    vm.prank(owner);
    harness.exposed_checkOwner();
  }

  function test_revert_checkOwner_notOwner() public {
    for (uint256 i; i < fuzzingAddresses.length; i++) {
      vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotOwnerHatWearer.selector));
      vm.prank(fuzzingAddresses[i]);
      harness.exposed_checkOwner();
    }
  }

  function test_happy_checkUnlocked() public view {
    // the harness starts out as unlocked, so this call should not revert
    harness.exposed_checkUnlocked();
  }

  function test_revert_checkUnlocked_locked() public {
    // lock the harness
    harness.exposed_lock();

    // confirm that its locked
    assertEq(harness.locked(), true, "harness should be locked");

    // checkUnlocked should revert
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    harness.exposed_checkUnlocked();
  }
}

contract OwnerSettingsInternals is WithHSGHarnessInstanceTest {
  function test_lock() public {
    harness.exposed_lock();

    assertEq(harness.locked(), true, "harness should be locked");
  }

  function test_fuzz_setOwnerHat(uint256 _newOwnerHat) public {
    vm.expectEmit();
    emit IHatsSignerGate.OwnerHatSet(_newOwnerHat);
    harness.exposed_setOwnerHat(_newOwnerHat);

    assertEq(harness.ownerHat(), _newOwnerHat, "ownerHat should be set to the new ownerHat");
  }

  function test_fuzz_setClaimableFor(bool _claimableFor) public {
    vm.expectEmit();
    emit IHatsSignerGate.ClaimableForSet(_claimableFor);
    harness.exposed_setClaimableFor(_claimableFor);

    assertEq(harness.claimableFor(), _claimableFor, "claimableFor should be set to the new claimableFor");
  }

  function test_fuzz_addSignerHats(uint256[] memory _signerHats) public {
    vm.assume(_signerHats.length > 0);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(_signerHats);
    harness.exposed_addSignerHats(_signerHats);

    for (uint256 i; i < _signerHats.length; i++) {
      assertTrue(harness.isValidSignerHat(_signerHats[i]), "signerHat should be valid");
    }
  }

  function test_addSignerHats_emptyArray() public {
    uint256[] memory empty = new uint256[](0);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(empty);
    harness.exposed_addSignerHats(empty);
  }

  function test_addSignerHats_duplicateHats() public {
    uint256 hatToDuplicate = 1;
    uint256[] memory duplicates = new uint256[](2);
    duplicates[0] = hatToDuplicate;
    duplicates[1] = hatToDuplicate;

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(duplicates);
    harness.exposed_addSignerHats(duplicates);

    assertTrue(harness.isValidSignerHat(hatToDuplicate), "signerHat should be valid");
  }

  function test_fuzz_setDelegatecallTarget(uint256 _targetIndex, bool _enabled) public {
    // bound the target index
    vm.assume(_targetIndex < fuzzingAddresses.length);

    address target = fuzzingAddresses[_targetIndex];

    // set the delegatecall target
    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, _enabled);
    harness.exposed_setDelegatecallTarget(target, _enabled);

    // now set it to the opposite enabled state
    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, !_enabled);
    harness.exposed_setDelegatecallTarget(target, !_enabled);
  }

  // function test_setThresholdConfig(uint8 _type, uint120 _min, uint120 _target) public { }

  function test_fuzz_setThresholdConfig_valid(uint8 _type, uint120 _min, uint120 _target) public {
    // ensure the threshold type is valid
    vm.assume(uint8(_type) < 2);
    IHatsSignerGate.TargetThresholdType targetType = IHatsSignerGate.TargetThresholdType(_type);

    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is valid
    if (targetType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      vm.assume(_target >= _min);
    } else {
      vm.assume(_target <= 10_000);
    }

    IHatsSignerGate.ThresholdConfig memory config =
      IHatsSignerGate.ThresholdConfig({ thresholdType: targetType, min: _min, target: _target });

    vm.expectEmit();
    emit IHatsSignerGate.ThresholdConfigSet(config);
    harness.exposed_setThresholdConfig(config);

    assertEq(
      abi.encode(harness.thresholdConfig()),
      abi.encode(config),
      "thresholdConfig should be set to the new thresholdConfig"
    );
  }

  function test_fuzz_revert_setThresholdConfig_invalidMin(uint8 _type, uint120 _target) public {
    // ensure the threshold type is valid
    vm.assume(uint8(_type) < 2);
    IHatsSignerGate.TargetThresholdType targetType = IHatsSignerGate.TargetThresholdType(_type);

    // ensure the min is invalid
    uint120 min = 0;

    // ensure the target is valid
    if (targetType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      vm.assume(_target >= min);
    } else {
      vm.assume(_target <= 10_000);
    }

    IHatsSignerGate.ThresholdConfig memory config =
      IHatsSignerGate.ThresholdConfig({ thresholdType: targetType, min: min, target: _target });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidAbsoluteTarget(uint120 _min, uint120 _target) public {
    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is invalid
    vm.assume(_target < _min);

    IHatsSignerGate.ThresholdConfig memory config = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: _min,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidProportionalTarget(uint120 _min, uint120 _target) public {
    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is invalid
    vm.assume(_target > 10_000);

    IHatsSignerGate.ThresholdConfig memory config = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: _min,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidThresholdType(uint8 _type, uint120 _min, uint120 _target) public {
    // ensure the threshold type is invalid
    vm.assume(uint8(_type) > 1);

    bytes memory rawConfig = abi.encode(uint8(_type), _min, _target); // thresholdType, min, target
    bytes memory callData = abi.encodeWithSelector(harness.exposed_setThresholdConfig.selector, rawConfig);

    (bool success,) = address(harness).call(callData);

    assertFalse(success, "setThresholdConfig should revert");
  }
}

contract RegisterSignerInternals is WithHSGHarnessInstanceTest {
  function _mockHatWearer(address _wearer, uint256 _hatId, bool _isWearer) internal {
    vm.mockCall(
      address(hats), abi.encodeWithSelector(hats.isWearerOfHat.selector, _wearer, _hatId), abi.encode(_isWearer)
    );
  }

  function test_fuzz_happy_registerSigner_allowRegistration(uint256 _hatToRegister, uint8 _signerIndex) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // the hat to register must not be zero
    vm.assume(_hatToRegister != 0);

    // ensure the hat is a valid signer hat
    // add the hat to the valid signer hats if it is not already valid
    if (!harness.isValidSignerHat(_hatToRegister)) {
      uint256[] memory hats = new uint256[](1);
      hats[0] = _hatToRegister;
      harness.exposed_addSignerHats(hats);
    }

    // ensure the signer is wearing the hat
    _mockHatWearer(signer, _hatToRegister, true);

    // register the signer, expecting an event
    vm.expectEmit();
    emit IHatsSignerGate.Registered(_hatToRegister, signer);
    harness.exposed_registerSigner(_hatToRegister, signer, true);

    assertEq(harness.claimedSignerHats(signer), _hatToRegister, "signer should be registered with the hat");
  }

  function test_fuzz_happy_registerSigner_disallowRegistration(
    uint256 _hatToRegister,
    uint8 _signerIndex,
    uint256 _registeredHat
  ) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // the hats should not be zero
    vm.assume(_hatToRegister != 0);
    vm.assume(_registeredHat != 0);

    // the hat to register should be different from the registered hat
    vm.assume(_hatToRegister != _registeredHat);

    // ensure both hats are valid signer hats
    uint256[] memory hats = new uint256[](2);
    if (!harness.isValidSignerHat(_hatToRegister)) {
      hats[0] = _hatToRegister;
    }
    if (!harness.isValidSignerHat(_registeredHat)) {
      hats[1] = _registeredHat;
    }
    harness.exposed_addSignerHats(hats); // will not revert if empty

    // ensure the signer is wearing the hat to register
    _mockHatWearer(signer, _hatToRegister, true);

    // register the signer for the first time
    _mockHatWearer(signer, _registeredHat, true);
    vm.expectEmit();
    emit IHatsSignerGate.Registered(_registeredHat, signer);
    harness.exposed_registerSigner(_registeredHat, signer, false);

    // ensure the signer now loses the registered hat
    _mockHatWearer(signer, _registeredHat, false);

    // attempt to re-register the signer, expecting a revert
    vm.expectEmit();
    emit IHatsSignerGate.Registered(_hatToRegister, signer);
    harness.exposed_registerSigner(_hatToRegister, signer, false);

    assertEq(harness.claimedSignerHats(signer), _hatToRegister, "signer should be registered with the new hat");
  }

  function test_fuzz_revert_registerSigner_invalidHat(
    uint256 _hatToRegister,
    uint8 _signerIndex,
    bool _allowRegistration
  ) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // ensure the hat is invalid
    vm.assume(!harness.isValidSignerHat(_hatToRegister));

    // register the signer, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, _hatToRegister));
    harness.exposed_registerSigner(_hatToRegister, signer, _allowRegistration);

    assertEq(harness.claimedSignerHats(signer), 0, "signer should not be registered");
  }

  function test_fuzz_revert_registerSigner_notSignerHatWearer(
    uint256 _hatToRegister,
    uint8 _signerIndex,
    bool _allowRegistration
  ) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // ensure the hat is valid
    if (!harness.isValidSignerHat(_hatToRegister)) {
      uint256[] memory hats = new uint256[](1);
      hats[0] = _hatToRegister;
      harness.exposed_addSignerHats(hats);
    }

    // ensure the signer is not wearing the hat
    _mockHatWearer(signer, _hatToRegister, false);

    // register the signer, expecting a revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signer));
    harness.exposed_registerSigner(_hatToRegister, signer, _allowRegistration);
  }

  function test_fuzz_revert_registerSigner_reregistrationNotAllowed_wearingRegisteredHat(
    uint256 _hatToRegister,
    uint8 _signerIndex,
    uint256 _registeredHat
  ) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // the hats should not be zero
    vm.assume(_hatToRegister != 0);
    vm.assume(_registeredHat != 0);

    // the hat to register should be different from the registered hat
    vm.assume(_hatToRegister != _registeredHat);

    // ensure both hats are valid signer hats
    uint256[] memory hats = new uint256[](2);
    if (!harness.isValidSignerHat(_hatToRegister)) {
      hats[0] = _hatToRegister;
    }
    if (!harness.isValidSignerHat(_registeredHat)) {
      hats[1] = _registeredHat;
    }
    harness.exposed_addSignerHats(hats); // will not revert if empty

    // ensure the signer is wearing the hat to register
    _mockHatWearer(signer, _hatToRegister, true);

    // ensure the signer is wearing the registered hat
    _mockHatWearer(signer, _registeredHat, true);

    // register the signer for the first time
    vm.expectEmit();
    emit IHatsSignerGate.Registered(_registeredHat, signer);
    harness.exposed_registerSigner(_registeredHat, signer, false);

    // register the signer, expecting a revert since they are still wearing their registered hat
    vm.expectRevert(IHatsSignerGate.ReregistrationNotAllowed.selector);
    harness.exposed_registerSigner(_hatToRegister, signer, false);
  }
}

contract AddingSignerInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_addSigner_happy(uint8[] memory _existingSignerIndices, uint8 _newSignerIndex) public {
    vm.assume(_existingSignerIndices.length > 0);
    vm.assume(uint256(_newSignerIndex) < fuzzingAddresses.length);

    // setup: get the existing signers on the safe
    for (uint256 i; i < _existingSignerIndices.length; i++) {
      // bound the signer index and get the signer
      vm.assume(uint256(_existingSignerIndices[i]) < fuzzingAddresses.length);
      address signer = fuzzingAddresses[_existingSignerIndices[i]];

      // add the signer
      harness.exposed_addSigner(signer);

      assertTrue(safe.isOwner(signer), "signer should be added to the safe");
      assertFalse(safe.isOwner(address(harness)), "the harness should no longer be an owner");

      // ensure the threshold is correct
      uint256 correctThreshold = harness.exposed_getNewThreshold(safe.getOwners().length);
      assertEq(safe.getThreshold(), correctThreshold, "the safe threshold should be correct");
    }

    // cache the existing owner count and threshold
    uint256 existingThreshold = safe.getThreshold();
    uint256 existingOwnerCount = safe.getOwners().length;

    // get the new signer
    address newSigner = fuzzingAddresses[_newSignerIndex];

    // is the new signer already an owner?
    bool isExistingSigner = safe.isOwner(newSigner);

    // add the new signer
    harness.exposed_addSigner(newSigner);

    assertTrue(safe.isOwner(newSigner), "new signer should be added to the safe");
    assertFalse(safe.isOwner(address(harness)), "the harness should no longer be an owner");

    if (isExistingSigner) {
      assertEq(safe.getOwners().length, existingOwnerCount, "there shouldn't be additional owners");
      assertEq(safe.getThreshold(), existingThreshold, "the safe threshold should not change");
    } else {
      assertEq(safe.getOwners().length, existingOwnerCount + 1, "there should be one more owner");
      uint256 correctThreshold = harness.exposed_getNewThreshold(safe.getOwners().length);
      assertEq(safe.getThreshold(), correctThreshold, "the safe threshold should be correct");
    }
  }

  function test_fuzz_addSigner_firstSigner(uint8 _newSignerIndex) public {
    // bound the new signer index and get the new signer
    vm.assume(uint256(_newSignerIndex) < fuzzingAddresses.length);
    address newSigner = fuzzingAddresses[_newSignerIndex];

    // add the new signer
    harness.exposed_addSigner(newSigner);

    assertEq(safe.getOwners().length, 1, "there should be one owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");
  }

  function test_fuzz_addSigner_secondSigner_notSigner(uint8 _existingSignerIndex, uint8 _newSignerIndex) public {
    // bound the existing and new signer indices and get the existing and new signers
    vm.assume(uint256(_existingSignerIndex) < fuzzingAddresses.length);
    vm.assume(uint256(_newSignerIndex) < fuzzingAddresses.length);
    address existingSigner = fuzzingAddresses[_existingSignerIndex];
    address newSigner = fuzzingAddresses[_newSignerIndex];

    // ensure the existing and new signers are different
    vm.assume(existingSigner != newSigner);

    // setup: add the existing signer
    harness.exposed_addSigner(existingSigner);

    // cache the existing owner count
    uint256 existingOwnerCount = safe.getOwners().length;

    // test: add the new signer
    harness.exposed_addSigner(newSigner);

    assertEq(safe.getOwners().length, existingOwnerCount + 1, "there should be one more owner");
    uint256 correctThreshold = harness.exposed_getNewThreshold(safe.getOwners().length);
    assertEq(safe.getThreshold(), correctThreshold, "the safe threshold should be correct");
  }

  function test_fuzz_addSigner_alreadySigner(uint8 _signerIndex) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // add the signer
    harness.exposed_addSigner(signer);

    assertEq(safe.getOwners().length, 1, "there should be one owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");

    // try to add the signer again, expecting no change
    harness.exposed_addSigner(signer);

    assertEq(safe.getOwners().length, 1, "there should be one owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");
  }
}

contract RemovingSignerInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_removeSigner(uint8[] memory _existingSignersIndices) public {
    // bound the array length
    vm.assume(_existingSignersIndices.length > 0);

    // setup: add the existing signers
    for (uint256 i; i < _existingSignersIndices.length; i++) {
      // bound the signer index and get the signer
      vm.assume(uint256(_existingSignersIndices[i]) < fuzzingAddresses.length);
      address signer = fuzzingAddresses[_existingSignersIndices[i]];

      // add the signer
      harness.exposed_addSigner(signer);
    }

    // cache the existing owner count
    uint256 existingOwnerCount = safe.getOwners().length;

    // randomly select an index to remove
    uint256 indexToRemove = vm.randomUint() % _existingSignersIndices.length;
    address signerToRemove = fuzzingAddresses[_existingSignersIndices[indexToRemove]];

    // test: remove the signer
    harness.exposed_removeSigner(signerToRemove);

    assertFalse(safe.isOwner(signerToRemove), "the signer should no longer be an owner");

    uint256 expectedOwnerCount = existingOwnerCount == 1 ? 1 : existingOwnerCount - 1;
    assertEq(safe.getOwners().length, expectedOwnerCount, "the owner count should decrease by one");

    uint256 correctThreshold = harness.exposed_getNewThreshold(safe.getOwners().length);
    assertEq(safe.getThreshold(), correctThreshold, "the safe threshold should be correct");
  }

  function test_fuzz_removeSigner_lastSigner(uint8 _signerIndex) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // setup: add the signer
    harness.exposed_addSigner(signer);

    // remove the signer
    harness.exposed_removeSigner(signer);

    assertFalse(safe.isOwner(signer), "the signer should no longer be an owner");
    assertEq(safe.getOwners().length, 1, "there should a single owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");
    assertTrue(safe.isOwner(address(harness)), "the harness should be the owner");
  }

  function test_fuzz_revert_removeSigner_notSigner(uint8 _signerIndex) public {
    // bound the signer index and get the signer
    vm.assume(uint256(_signerIndex) < fuzzingAddresses.length);
    address signer = fuzzingAddresses[_signerIndex];

    // try to remove the signer, expecting tx success but nothing to change
    harness.exposed_removeSigner(signer);

    assertEq(safe.getOwners().length, 1, "there should a single owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");
    assertTrue(safe.isOwner(address(harness)), "the harness should be the owner");
  }
}

contract TransactionValidationInternals is WithHSGHarnessInstanceTest {
  function test_checkModuleTransaction_calltoNonSafeTarget() public { }

  function test_checkModuleTransaction_delegatecallToApprovedTarget() public { }

  function test_revert_checkModuleTransaction_delegatecallToUnapprovedTarget() public { }

  function test_revert_checkModuleTransaction_callToSafe() public { }

  function test_checkSafeState() public { }

  function test_revert_checkSafeState_removesHSGAsGuard() public { }

  function test_revert_checkSafeState_changesThreshold() public { }

  function test_revert_checkSafeState_changesOwners() public { }

  function test_revert_checkSafeState_changesFallbackHandler() public { }

  function test_revert_checkSafeState_addsModule() public { }

  function test_revert_checkSafeState_disablesHSGAsModule() public { }
}

contract ViewInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_getRequiredValidSignatures() public { }

  function test_getRequiredValidSignatures_absolute() public { }

  function test_getRequiredValidSignatures_proportional() public { }

  function test_getNewThreshold() public { }

  function test_getNewThreshold_exceedsOwnerCount() public { }
}
