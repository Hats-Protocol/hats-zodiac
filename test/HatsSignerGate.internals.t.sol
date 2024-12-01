// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, WithHSGHarnessInstanceTest } from "./TestSuite.t.sol";
import { IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { SafeManagerLib } from "../src/lib/SafeManagerLib.sol";

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

  function test_fuzz_addSignerHats(uint8 _numHats) public {
    // Bound number of hats to a semi-reasonable range
    uint256 numHats = bound(_numHats, 1, 100);

    // Create array of signer hats
    uint256[] memory signerHats = _getRandomSignerHats(numHats);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(signerHats);
    harness.exposed_addSignerHats(signerHats);

    // Verify each hat was properly registered
    for (uint256 i; i < signerHats.length; i++) {
      assertTrue(harness.isValidSignerHat(signerHats[i]), "signerHat should be valid");
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

    assertEq(harness.registeredSignerHats(signer), _hatToRegister, "signer should be registered with the hat");
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

    assertEq(harness.registeredSignerHats(signer), _hatToRegister, "signer should be registered with the new hat");
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

    assertEq(harness.registeredSignerHats(signer), 0, "signer should not be registered");
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
  function test_fuzz_addSigner_happy(uint8 _numExistingSigners, uint8 _newSignerIndex) public {
    // Bound the new signer index
    vm.assume(uint256(_newSignerIndex) < fuzzingAddresses.length);

    // add random existing signers
    _addRandomSigners(_numExistingSigners);

    // Cache the existing owner count and threshold
    uint256 existingThreshold = safe.getThreshold();
    uint256 existingOwnerCount = safe.getOwners().length;

    // Get the new signer
    address newSigner = fuzzingAddresses[_newSignerIndex];

    // Check if the new signer is already an owner
    bool isExistingSigner = safe.isOwner(newSigner);

    // Add the new signer
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
  function test_fuzz_removeSigner(uint8 _numExistingSigners) public {
    // Add random existing signers
    _addRandomSigners(_numExistingSigners);

    // cache the existing owner count
    uint256 existingOwnerCount = safe.getOwners().length;

    // randomly select an index to remove
    uint256 indexToRemove = uint256(keccak256(abi.encode(vm.randomUint(), "remove"))) % existingOwnerCount;
    address signerToRemove = safe.getOwners()[indexToRemove];

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

    // try to remove the signer, expecting a revert
    vm.expectRevert(SafeManagerLib.SafeTransactionFailed.selector);
    harness.exposed_removeSigner(signer);

    assertEq(safe.getOwners().length, 1, "there should a single owner");
    assertEq(safe.getThreshold(), 1, "the safe threshold should be one");
    assertTrue(safe.isOwner(address(harness)), "the harness should be the owner");
  }
}

contract TransactionValidationInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_checkModuleTransaction_callToNonSafeTarget(uint8 _toIndex) public {
    // bound the to index and get the to address
    vm.assume(uint256(_toIndex) < fuzzingAddresses.length);
    address to = fuzzingAddresses[_toIndex];

    // test: _checkModuleTransaction should not revert
    harness.exposed_checkModuleTransaction(to, Enum.Operation.Call, safe);
  }

  function test_fuzz_checkModuleTransaction_delegatecallToApprovedTarget(
    uint8 _toIndex,
    uint8 _numExistingSigners,
    uint8 _type,
    uint8 _min,
    uint16 _target
  ) public {
    // bound the to index and get the to address
    vm.assume(uint256(_toIndex) < fuzzingAddresses.length);
    address to = fuzzingAddresses[_toIndex];

    // enable the target
    harness.exposed_setDelegatecallTarget(to, true);
    assertTrue(harness.enabledDelegatecallTargets(to), "the target should be enabled");

    // set a new threshold config based on the provided values; this will create a new threshold value to check
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);
    harness.exposed_setThresholdConfig(config);

    // add some existing owners; this will create a new owners hash to check
    _addRandomSigners(_numExistingSigners);

    // cache the existing owners hash, threshold, and fallback handler
    bytes32 existingOwnersHash = keccak256(abi.encode(safe.getOwners()));
    uint256 existingThreshold = safe.getThreshold();
    address existingFallbackHandler = SafeManagerLib.getSafeFallbackHandler(safe);

    // test: _checkModuleTransaction should not revert
    harness.exposed_checkModuleTransaction(to, Enum.Operation.DelegateCall, safe);

    // ensure the existing owners hash, threshold, and fallback handler are unchanged
    assertCorrectTransientState(existingOwnersHash, existingThreshold, existingFallbackHandler);
  }

  function test_fuzz_revert_checkModuleTransaction_delegatecallToUnapprovedTarget(uint8 _toIndex) public {
    // bound the to index and get the to address
    vm.assume(uint256(_toIndex) < fuzzingAddresses.length);
    address to = fuzzingAddresses[_toIndex];

    // ensure the target is not approved
    assertFalse(harness.enabledDelegatecallTargets(to), "the target should not be enabled");

    // test: _checkModuleTransaction should revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    harness.exposed_checkModuleTransaction(to, Enum.Operation.DelegateCall, safe);
  }

  function test_revert_checkModuleTransaction_callToSafe() public {
    // test: _checkModuleTransaction should revert
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    harness.exposed_checkModuleTransaction(address(safe), Enum.Operation.Call, safe);
  }

  function test_checkSafeState() public {
    // set the owners hash, fallback handler, and threshold in transient state to bypass those errors
    harness.setExistingOwnersHash(keccak256(abi.encode(safe.getOwners())));
    harness.setExistingFallbackHandler(SafeManagerLib.getSafeFallbackHandler(safe));
    harness.setExistingThreshold(safe.getThreshold());

    // test: _checkSafeState should not revert
    harness.exposed_checkSafeState(safe);
  }

  function test_revert_checkSafeState_removesHSGAsGuard() public {
    // remove the HSG as a guard
    vm.prank(address(safe));
    safe.setGuard(address(0));
    assertFalse(SafeManagerLib.getSafeGuard(safe) == address(this), "the HSG is no longer a guard");

    // test: _checkSafeState should revert
    vm.expectRevert(IHatsSignerGate.CannotDisableThisGuard.selector);
    harness.exposed_checkSafeState(safe);
  }

  function test_revert_checkSafeState_changesThreshold() public {
    assertEq(harness.existingThreshold(), 0, "cached threshold is 0");

    // test: _checkSafeState should revert since the threshold has not be cached in transient state
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeThreshold.selector));
    harness.exposed_checkSafeState(safe);
  }

  function test_revert_checkSafeState_changesOwners() public {
    // set the threshold in transient state to bypass that error
    harness.setExistingThreshold(safe.getThreshold());

    assertEq(harness.existingOwnersHash(), bytes32(0), "cached owners hash is 0");

    // test: _checkSafeState should revert since the owners hash has not be cached in transient state
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeOwners.selector));
    harness.exposed_checkSafeState(safe);
  }

  function test_revert_checkSafeState_changesFallbackHandler() public { }

  function test_revert_checkSafeState_addsModule(uint256 _moduleIndex) public {
    // set the owners hash, fallback handler, and threshold in transient state to bypass those errors
    harness.setExistingOwnersHash(keccak256(abi.encode(safe.getOwners())));
    harness.setExistingFallbackHandler(SafeManagerLib.getSafeFallbackHandler(safe));
    harness.setExistingThreshold(safe.getThreshold());

    // enable a new module
    vm.assume(_moduleIndex < fuzzingAddresses.length);
    address module = fuzzingAddresses[_moduleIndex];
    vm.prank(address(safe));
    safe.enableModule(module);
    assertTrue(safe.isModuleEnabled(module), "a new module is added");

    // test: _checkSafeState should revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeModules.selector));
    harness.exposed_checkSafeState(safe);
  }

  function test_revert_checkSafeState_disablesHSGAsModule() public {
    // set the owners hash, fallback handler, and threshold in transient state to bypass those errors
    harness.setExistingOwnersHash(keccak256(abi.encode(safe.getOwners())));
    harness.setExistingFallbackHandler(SafeManagerLib.getSafeFallbackHandler(safe));
    harness.setExistingThreshold(safe.getThreshold());

    // disable HSG as a module
    vm.prank(address(safe));
    safe.disableModule({ prevModule: SENTINELS, module: address(harness) });
    assertFalse(safe.isModuleEnabled(address(harness)), "HSG is no longer a module");

    // test: _checkSafeState should revert
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.CannotChangeModules.selector));
    harness.exposed_checkSafeState(safe);
  }
}

contract ViewInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_getRequiredValidSignatures_absolute(uint8 _min, uint16 _target, uint16 _ownerCount) public {
    IHatsSignerGate.ThresholdConfig memory config =
      _createValidThresholdConfig(IHatsSignerGate.TargetThresholdType.ABSOLUTE, _min, _target);

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the required valid signatures
    uint256 actual = harness.exposed_getRequiredValidSignatures(_ownerCount);
    uint256 expected = _calcAbsoluteRequiredValidSignatures(_ownerCount, config.min, config.target);
    // ensure the actual is correct
    assertEq(actual, expected, "the required valid signatures should be correct");
  }

  function test_fuzz_getRequiredValidSignatures_absolute_ownerCountIsMin(uint8 _min, uint16 _target) public {
    IHatsSignerGate.ThresholdConfig memory config =
      _createValidThresholdConfig(IHatsSignerGate.TargetThresholdType.ABSOLUTE, _min, _target);

    // ensure the ownerCount == the min
    uint256 ownerCount = config.min;

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the required valid signatures
    uint256 actual = harness.exposed_getRequiredValidSignatures(ownerCount);
    uint256 expected = config.min;
    // ensure the actual is correct
    assertEq(actual, expected, "the required valid signatures should be the min");
  }

  function test_fuzz_getRequiredValidSignatures_absolute_targetOwnerCount(uint8 _min, uint16 _target) public {
    IHatsSignerGate.ThresholdConfig memory config =
      _createValidThresholdConfig(IHatsSignerGate.TargetThresholdType.ABSOLUTE, _min, _target);

    // ensure the _ownerCount is at the target
    uint256 ownerCount = config.target;

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the required valid signatures
    uint256 actual = harness.exposed_getRequiredValidSignatures(ownerCount);
    uint256 expected = _calcAbsoluteRequiredValidSignatures(ownerCount, config.min, config.target);
    // ensure the actual is correct
    assertEq(actual, expected, "the required valid signatures should be the target");
  }

  function test_fuzz_getRequiredValidSignatures_proportional(uint8 _min, uint16 _target, uint16 _ownerCount) public {
    IHatsSignerGate.ThresholdConfig memory config =
      _createValidThresholdConfig(IHatsSignerGate.TargetThresholdType.PROPORTIONAL, _min, _target);

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the required valid signatures
    uint256 actual = harness.exposed_getRequiredValidSignatures(_ownerCount);
    console2.log("actual", actual);
    uint256 expected = _calcProportionalRequiredValidSignatures(_ownerCount, config.min, config.target);
    console2.log("expected", expected);
    // ensure the actual is correct
    assertEq(actual, expected, "the required valid signatures should be correct");
  }

  function test_fuzz_getRequiredValidSignatures_ownerCountLtMin(uint8 _type, uint8 _min, uint16 _target) public {
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    // ensure the ownerCount is less than the min
    // generate a random ownerCount such that ownerCount < min
    uint256 ownerCount = vm.randomUint() % config.min;

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the required valid signatures
    uint256 actual = harness.exposed_getRequiredValidSignatures(ownerCount);
    uint256 expected = config.min;
    // ensure the actual is correct
    assertEq(actual, expected, "the required valid signatures should be the min");
  }

  function test_fuzz_getNewThreshold(uint8 _type, uint8 _min, uint16 _target, uint16 _ownerCount) public {
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // get the new threshold
    uint256 actual = harness.exposed_getNewThreshold(_ownerCount);

    // calculate the expected new threshold
    uint256 requiredSignatures = harness.exposed_getRequiredValidSignatures(_ownerCount);
    uint256 expected = _ownerCount < requiredSignatures ? _ownerCount : requiredSignatures;

    // ensure the actual is correct
    assertEq(actual, expected, "the new threshold should be correct");
  }

  function test_fuzz_getNewThreshold_exceedsOwnerCount(uint8 _type, uint8 _min, uint16 _target) public {
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    // set the threshold config
    harness.exposed_setThresholdConfig(config);

    // generate a random owner count that is lower than the min
    uint256 ownerCount = vm.randomUint() % config.min;

    // get the new threshold
    uint256 actual = harness.exposed_getNewThreshold(ownerCount);
    uint256 expected = ownerCount;
    // ensure the actual is correct
    assertEq(actual, expected, "the new threshold should be the owner count");
  }

  function test_fuzz_countValidSigners(uint8 _numSigners) public {
    // ensure we have between 1 and the number of fuzzing addresses
    _numSigners = uint8(bound(_numSigners, 1, fuzzingAddresses.length));

    // Create fixed-size arrays
    address[] memory signers = new address[](_numSigners);
    bool[] memory used = new bool[](fuzzingAddresses.length);
    uint256 expectedValidCount;

    console2.log("signerHat", signerHat);

    // Fill signers array with unique addresses
    uint256 count;
    uint256 attempts;
    while (count < _numSigners && attempts < 100) {
      // Added attempts limit as safety
      // Generate index using a random uint and current attempt
      uint256 index = uint256(keccak256(abi.encode(vm.randomUint(), attempts))) % fuzzingAddresses.length;

      if (!used[index]) {
        used[index] = true;
        signers[count] = fuzzingAddresses[index];

        // Set validity and track expected count
        bool isValid = uint256(keccak256(abi.encode(vm.randomUint(), "validity", count))) % 2 == 0;
        _setSignerValidity(signers[count], signerHat, isValid);
        if (isValid) {
          // register the signer
          harness.exposed_registerSigner(signerHat, signers[count], false);
          // increment the expected valid count
          expectedValidCount++;
        }

        count++;
      }
      attempts++;
    }

    // Verify the count matches expected
    assertEq(harness.exposed_countValidSigners(signers), expectedValidCount, "valid signer count should match expected");
  }
}

contract CountingValidSignaturesInternals is WithHSGHarnessInstanceTest {
  function test_fuzz_countValidSignatures_contractSignature(uint256 _sigCount) public {
    // ensure we have between 1 and the number of signer addresses
    _sigCount = bound(_sigCount, 1, signerAddresses.length);

    // generate random contract signatures
    (bytes memory signatures, uint256 expectedValidCount) = _generateUniqueNonECDSASignatures(_sigCount, false, harness);

    // test: count the valid signatures
    uint256 actual = harness.exposed_countValidSignatures(bytes32(0), signatures, _sigCount);

    // ensure the actual is correct
    assertEq(actual, expectedValidCount, "valid signer count should match expected");
  }

  function test_fuzz_countValidSignatures_approvedHash(uint256 _sigCount) public {
    // ensure we have between 1 and the number of signer addresses
    _sigCount = bound(_sigCount, 1, signerAddresses.length);

    // generate random approved hash signatures
    (bytes memory signatures, uint256 expectedValidCount) = _generateUniqueNonECDSASignatures(_sigCount, true, harness);

    // test: count the valid signatures
    uint256 actual = harness.exposed_countValidSignatures(bytes32(0), signatures, _sigCount);

    // ensure the actual is correct
    assertEq(actual, expectedValidCount, "valid signer count should match expected");
  }

  function test_fuzz_countValidSignatures_ethSign(bytes32 _dataHash, uint256 _sigCount) public {
    // ensure we have between 1 and the number of signer addresses
    _sigCount = bound(_sigCount, 1, signerAddresses.length);

    // generate random eth_sign signatures
    (bytes memory signatures, uint256 expectedValidCount) =
      _generateUniqueECDSASignatures(_dataHash, _sigCount, true, harness);

    // test: count the valid signatures
    uint256 actual = harness.exposed_countValidSignatures(_dataHash, signatures, _sigCount);

    // ensure the actual is correct
    assertEq(actual, expectedValidCount, "valid signer count should match expected");
  }

  function test_fuzz_countValidSignatures_default(bytes32 _dataHash, uint256 _sigCount) public {
    // ensure we have between 1 and the number of signer addresses
    _sigCount = bound(_sigCount, 1, signerAddresses.length);

    // generate random signatures
    (bytes memory signatures, uint256 expectedValidCount) =
      _generateUniqueECDSASignatures(_dataHash, _sigCount, false, harness);

    // test: count the valid signatures
    uint256 actual = harness.exposed_countValidSignatures(_dataHash, signatures, _sigCount);

    // ensure the actual is correct
    assertEq(actual, expectedValidCount, "valid signer count should match expected");
  }
}
