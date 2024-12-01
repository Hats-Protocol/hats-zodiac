// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import {
  Enum, ISafe, TestSuite, WithHSGInstanceTest, WithHSGHarnessInstanceTest, HatsSignerGate
} from "./TestSuite.t.sol";
import { IHats, IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { DeployInstance } from "../script/HatsSignerGate.s.sol";
import { IAvatar } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { IModuleManager } from "../src/lib/safe-interfaces/IModuleManager.sol";
import { GuardableUnowned } from "../src/lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { TestGuard } from "./mocks/TestGuard.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeManagerLib } from "../src/lib/SafeManagerLib.sol";

contract ImplementationDeployment is TestSuite {
  // errors from dependencies
  error InvalidInitialization();

  function test_constructorArgs() public view {
    assertEq(address(implementationHSG.HATS()), address(hats));

    (address safe, address fallBack, address multisend, address factory) =
      implementationHSG.getSafeDeployParamAddresses();
    assertEq(safe, address(singletonSafe));
    assertEq(fallBack, address(safeFallbackLibrary));
    assertEq(multisend, address(safeMultisendLibrary));
    assertEq(factory, address(safeFactory));
  }

  function test_version() public view {
    assertEq(implementationHSG.version(), "2.0.0");
  }

  function test_ownerHat() public view {
    assertEq(implementationHSG.ownerHat(), 1);
  }

  function test_revert_initializerCalledTwice() public {
    IHatsSignerGate.SetupParams memory setupParams = IHatsSignerGate.SetupParams({
      ownerHat: ownerHat,
      signerHats: signerHats,
      safe: address(safe),
      thresholdConfig: thresholdConfig,
      locked: false,
      claimableFor: false,
      implementation: address(implementationHSG),
      hsgGuard: address(tstGuard),
      hsgModules: tstModules
    });
    bytes memory initializeParams = abi.encode(setupParams);
    vm.expectRevert(InvalidInitialization.selector);
    implementationHSG.setUp(initializeParams);
  }
}

contract InstanceDeployment is TestSuite {
  // errors from dependencies
  error InvalidInitialization();

  function test_initialParams_existingSafe(bool _locked, bool _claimableFor) public {
    // deploy safe with this contract as the single owner
    address[] memory owners = new address[](1);
    owners[0] = address(this);
    ISafe testSafe = _deploySafe(owners, 1, TEST_SALT_NONCE);

    instance = _deployHSG({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _safe: address(testSafe),
      _expectedError: bytes4(0), // no expected error
      _locked: _locked,
      _claimableFor: _claimableFor,
      _hsgGuard: address(tstGuard),
      _hsgModules: tstModules,
      _verbose: false
    });

    assertEq(instance.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(instance.thresholdConfig(), thresholdConfig);
    assertEq(address(instance.safe()), address(testSafe));
    assertEq(address(instance.implementation()), address(implementationHSG));
    assertEq(instance.locked(), _locked);
    assertEq(instance.claimableFor(), _claimableFor);
    assertEq(address(instance.getGuard()), address(tstGuard));
    assertCorrectModules(tstModules);
    assertEq(address(instance.HATS()), address(hats));

    // check that the default delegatecall targets are enabled
    for (uint256 i; i < defaultDelegatecallTargets.length; ++i) {
      assertTrue(instance.enabledDelegatecallTargets(defaultDelegatecallTargets[i]), "default target should be enabled");
    }
  }

  function test_initialParams_newSafe(bool _locked, bool _claimableFor) public {
    (instance, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _locked: _locked,
      _claimableFor: _claimableFor,
      _hsgGuard: address(tstGuard),
      _hsgModules: tstModules,
      _verbose: false
    });

    assertEq(instance.ownerHat(), ownerHat);
    assertValidSignerHats(signerHats);
    assertEq(instance.thresholdConfig(), thresholdConfig);
    assertEq(address(instance.HATS()), address(hats));
    assertEq(address(instance.safe()), address(safe));
    assertEq(address(instance.implementation()), address(implementationHSG));
    assertEq(_getSafeGuard(address(safe)), address(instance));
    assertTrue(safe.isModuleEnabled(address(instance)));
    assertEq(safe.getOwners()[0], address(instance));
    assertEq(instance.locked(), _locked);
    assertEq(instance.claimableFor(), _claimableFor);
    assertEq(address(instance.getGuard()), address(tstGuard));
    assertCorrectModules(tstModules);

    // check that the default delegatecall targets are enabled
    for (uint256 i; i < defaultDelegatecallTargets.length; ++i) {
      assertTrue(instance.enabledDelegatecallTargets(defaultDelegatecallTargets[i]), "default target should be enabled");
    }
  }

  function test_revert_initializerCalledTwice() public {
    (instance, safe) = _deployHSGAndSafe({
      _ownerHat: ownerHat,
      _signerHats: signerHats,
      _thresholdConfig: thresholdConfig,
      _locked: false,
      _claimableFor: false,
      _hsgGuard: address(tstGuard),
      _hsgModules: tstModules,
      _verbose: false
    });

    IHatsSignerGate.SetupParams memory setupParams = IHatsSignerGate.SetupParams({
      ownerHat: ownerHat,
      signerHats: signerHats,
      safe: address(safe),
      thresholdConfig: thresholdConfig,
      locked: false,
      claimableFor: false,
      implementation: address(implementationHSG),
      hsgGuard: address(tstGuard),
      hsgModules: tstModules
    });
    bytes memory initializeParams = abi.encode(setupParams);
    // console2.logBytes(initializeParams);
    vm.expectRevert(InvalidInitialization.selector);
    instance.setUp(initializeParams);
  }
}

/// @dev see HatsSignerGate.internals.t.sol:ClaimingSignerInternals for tests of claimSigner internal logic
contract ClaimingSigner is WithHSGInstanceTest {
  /// forge-config: default.fuzz.runs = 200
  function test_fuzz_happy_claimSigner(uint256 _seed) public {
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer
    _setSignerValidity(caller, signerHat, true);

    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHat, caller);
    vm.prank(caller);
    instance.claimSigner(signerHat);

    assertEq(instance.registeredSignerHats(caller), signerHat, "caller should have registered the signer hat");
    assertTrue(instance.isValidSigner(caller), "caller should be a valid signer");
    assertTrue(safe.isOwner(caller), "caller should be on the safe");
  }

  function test_fuzz_claimSigner_alreadyRegistered_differentHats(uint256 _seed) public {
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer for two valid signer hats
    _setSignerValidity(caller, signerHats[0], true);
    _setSignerValidity(caller, signerHats[1], true);
    // claim the first signer hat
    vm.prank(caller);
    instance.claimSigner(signerHats[0]);

    // claim again with a different signer hat
    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHats[1], caller);
    vm.prank(caller);
    instance.claimSigner(signerHats[1]);

    assertEq(instance.registeredSignerHats(caller), signerHats[1], "caller should have registered the new signer hat");
    assertTrue(instance.isValidSigner(caller), "caller should be a valid signer");
    assertTrue(safe.isOwner(caller), "caller should be on the safe");
  }

  function test_fuzz_claimSigner_alreadyRegistered_sameHat(uint256 _seed) public {
    // get a random valid signer hat
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer for the signer hat
    _setSignerValidity(caller, signerHat, true);

    // claim for the first time
    vm.prank(caller);
    instance.claimSigner(signerHat);

    // claim again with the same signer hat
    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHat, caller);
    vm.prank(caller);
    instance.claimSigner(signerHat);

    assertEq(instance.registeredSignerHats(caller), signerHat, "caller should be registered for the same hat");
    assertTrue(instance.isValidSigner(caller), "caller should be a valid signer");
    assertTrue(safe.isOwner(caller), "caller should be on the safe");
  }

  function test_fuzz_claimSigner_notRegistered_onSafe(uint256 _seed) public {
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer
    _setSignerValidity(caller, signerHat, true);

    // add the signer to the safe directly
    vm.prank(address(safe));
    safe.addOwnerWithThreshold(caller, 1);

    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHat, caller);
    vm.prank(caller);
    instance.claimSigner(signerHat);

    assertEq(instance.registeredSignerHats(caller), signerHat, "caller should have registered the signer hat");
    assertTrue(instance.isValidSigner(caller), "caller should be a valid signer");
    assertTrue(safe.isOwner(caller), "caller should be on the safe");
  }

  function test_fuzz_revert_invalidSignerHat(uint256 _signerHat, uint256 _seed) public {
    vm.assume(_signerHat > 0); // the 0 hat id does not exist
    vm.assume(!instance.isValidSignerHat(_signerHat));
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer; we need to use the mock because the signer hat is not real
    _mockHatWearer(caller, _signerHat, true);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, _signerHat));
    vm.prank(caller);
    instance.claimSigner(_signerHat);

    assertNotEq(instance.registeredSignerHats(caller), _signerHat, "caller should not have registered the signer hat");
    assertFalse(instance.isValidSigner(caller), "caller should not be a valid signer");
    assertFalse(safe.isOwner(caller), "caller should not be on the safe");
  }

  function test_fuzz_revert_notWearingSignerHat(uint256 _seed) public {
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address caller = _getRandomAddress(_seed);
    // make caller a valid signer; we need to use the mock because the signer hat is not real
    _setSignerValidity(caller, signerHat, false);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, caller));
    vm.prank(caller);
    instance.claimSigner(signerHat);

    assertNotEq(instance.registeredSignerHats(caller), signerHat, "caller should not have registered the signer hat");
    assertFalse(instance.isValidSigner(caller), "caller should not be a valid signer");
    assertFalse(safe.isOwner(caller), "caller should not be on the safe");
  }

  function test_fuzz_multipleSigners_multipleHats(uint256 _count, uint256 _seed) public {
    // bound the count to be between 1 and the number of signer hats
    _count = bound(_count, 1, signerHats.length);

    for (uint256 i; i < _count; ++i) {
      uint256 seed = uint256(keccak256(abi.encode(_seed, i)));
      uint256 signerHat = _getRandomValidSignerHat(seed);
      address caller = _getRandomAddress(seed);
      _setSignerValidity(caller, signerHat, true);

      vm.expectEmit();
      emit IHatsSignerGate.Registered(signerHat, caller);
      vm.prank(caller);
      instance.claimSigner(signerHat);

      assertEq(instance.registeredSignerHats(caller), signerHat, "caller should have registered the signer hat");
      assertTrue(instance.isValidSigner(caller), "caller should be a valid signer");
      assertTrue(safe.isOwner(caller), "caller should be on the safe");
    }
  }
}

contract ClaimingSignerFor is WithHSGInstanceTest {
  function test_happy_claimSignerFor(uint256 _seed) public isClaimableFor(true) {
    // get a random valid signer hat
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address signer = _getRandomAddress(_seed);
    // make signer a valid signer for the signer hat
    _setSignerValidity(signer, signerHat, true);

    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHat, signer);
    instance.claimSignerFor(signerHat, signer);

    assertEq(instance.registeredSignerHats(signer), signerHat, "signer should have registered the signer hat");
    assertTrue(instance.isValidSigner(signer), "signer should be a valid signer");
    assertTrue(safe.isOwner(signer), "signer should be on the safe");
  }

  function test_alreadyOwner_notRegistered(uint256 _seed) public isClaimableFor(true) {
    // get a random valid signer hat
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address signer = _getRandomAddress(_seed);
    // add the signer to the safe directly
    vm.prank(address(safe));
    safe.addOwnerWithThreshold(signer, 1);

    // make signer a valid signer for the signer hat
    _setSignerValidity(signer, signerHat, true);

    // claim the signer
    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHat, signer);
    instance.claimSignerFor(signerHat, signer);

    assertEq(instance.registeredSignerHats(signer), signerHat, "signer should have registered the signer hat");
    assertTrue(instance.isValidSigner(signer), "signer should be a valid signer");
    assertTrue(safe.isOwner(signer), "signer should be on the safe");
  }

  function test_revert_notClaimableFor(uint256 _seed) public isClaimableFor(false) {
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address signer = _getRandomAddress(_seed);
    // make signer a valid signer for the signer hat
    _setSignerValidity(signer, signerHat, true);

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    instance.claimSignerFor(signerHat, signer);

    assertNotEq(instance.registeredSignerHats(signer), signerHat, "signer should not have registered the signer hat");
    assertFalse(instance.isValidSigner(signer), "signer should not be a valid signer");
    assertFalse(safe.isOwner(signer), "signer should not be on the safe");
  }

  function test_revert_invalidSignerHat(uint256 _signerHat, uint256 _seed) public isClaimableFor(true) {
    vm.assume(_signerHat > 0); // the 0 hat id does not exist
    vm.assume(!instance.isValidSignerHat(_signerHat)); // this test is for invalid signer hats
    address signer = _getRandomAddress(_seed);
    // make signer a valid signer for the signer hat; we need to use the mock because the signer hat is not real
    _mockHatWearer(signer, _signerHat, true);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, _signerHat));
    instance.claimSignerFor(_signerHat, signer);

    assertNotEq(instance.registeredSignerHats(signer), _signerHat, "signer should not have registered the signer hat");
    assertFalse(instance.isValidSigner(signer), "signer should not be a valid signer");
    assertFalse(safe.isOwner(signer), "signer should not be on the safe");
  }

  function test_revert_notWearingSignerHat(uint256 _seed) public isClaimableFor(true) {
    uint256 signerHat = _getRandomValidSignerHat(_seed);
    address signer = _getRandomAddress(_seed);
    // make signer a invalid signer for the signer hat
    _setSignerValidity(signer, signerHat, false);

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signer));
    instance.claimSignerFor(signerHat, signer);

    assertNotEq(instance.registeredSignerHats(signer), signerHat, "signer should not have registered the signer hat");
    assertFalse(instance.isValidSigner(signer), "signer should not be a valid signer");
    assertFalse(safe.isOwner(signer), "signer should not be on the safe");
  }

  function test_revert_alreadyRegistered_stillWearingRegisteredHat(uint256 _seed) public isClaimableFor(true) {
    address signer = _getRandomAddress(_seed);
    // make signer a valid signer for two signer hats
    _setSignerValidity(signer, signerHats[0], true);
    _setSignerValidity(signer, signerHats[1], true);

    // claim for the first time
    instance.claimSignerFor(signerHats[0], signer);

    // claim again with a different signer hat
    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.ReregistrationNotAllowed.selector));
    instance.claimSignerFor(signerHats[1], signer);

    assertEq(instance.registeredSignerHats(signer), signerHats[0], "signer should have registered the first signer hat");
    assertTrue(instance.isValidSigner(signer), "signer should still be a valid signer");
    assertTrue(safe.isOwner(signer), "signer should still be on the safe");
  }

  function test_alreadyRegistered_notWearingRegisteredHat(uint256 _seed) public isClaimableFor(true) {
    address signer = _getRandomAddress(_seed);
    // make signer a valid signer for two signer hats
    _setSignerValidity(signer, signerHats[0], true);
    _setSignerValidity(signer, signerHats[1], true);

    // claim for the first time
    instance.claimSignerFor(signerHats[0], signer);

    // signer loses the first signer hat
    _setSignerValidity(signer, signerHats[0], false);

    // claim again with the second signer hat
    vm.expectEmit();
    emit IHatsSignerGate.Registered(signerHats[1], signer);
    instance.claimSignerFor(signerHats[1], signer);

    assertEq(
      instance.registeredSignerHats(signer), signerHats[1], "signer should have registered the second signer hat"
    );
    assertTrue(instance.isValidSigner(signer), "signer should be a valid signer");
    assertTrue(safe.isOwner(signer), "signer should be on the safe");
  }
}

contract ClaimingSignersFor is WithHSGInstanceTest {
  function test_startingEmpty_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    instance.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    // claim the signers, expecting the registered event to be emitted for each
    for (uint256 i; i < _signerCount; ++i) {
      vm.expectEmit();
      emit IHatsSignerGate.Registered(signerHat, signerAddresses[i]);
    }
    instance.claimSignersFor(hatIds, claimers);

    assertEq(instance.validSignerCount(), _signerCount, "incorrect valid signer count");
    assertEq(safe.getOwners().length, _signerCount, "incorrect owner count");
  }

  function test_startingWith1Signer_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    instance.setClaimableFor(true);

    // add one signer to get rid of the placeholder owner
    _addSignersSameHat(1, signerHat);
    assertEq(instance.validSignerCount(), 1, "valid signer count should be 1");
    assertEq(safe.getOwners().length, 1, "owner count should be 1");

    // create the necessary arrays, starting with the next signer
    address[] memory claimers = new address[](_signerCount - 1);
    uint256[] memory hatIds = new uint256[](_signerCount - 1);
    for (uint256 i; i < _signerCount - 1; ++i) {
      claimers[i] = signerAddresses[i + 1];
      hatIds[i] = signerHat;
    }

    // claim the signers, expecting the registered event to be emitted for each
    for (uint256 i; i < _signerCount - 1; ++i) {
      vm.expectEmit();
      emit IHatsSignerGate.Registered(signerHat, signerAddresses[i + 1]);
    }
    instance.claimSignersFor(hatIds, claimers);

    assertEq(instance.validSignerCount(), _signerCount, "incorrect valid signer count");
    assertEq(safe.getOwners().length, _signerCount, "incorrect owner count");
  }

  function test_alreadyOwnerNotRegistered_happy(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // add _signerCount signers directly to the safe by pranking the safe
    for (uint256 i; i < _signerCount; ++i) {
      vm.prank(address(safe));
      safe.addOwnerWithThreshold(signerAddresses[i], 1);
    }

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    instance.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    // claim the signers, expecting the registered event to be emitted for each
    for (uint256 i; i < _signerCount; ++i) {
      vm.expectEmit();
      emit IHatsSignerGate.Registered(signerHat, signerAddresses[i]);
    }
    instance.claimSignersFor(hatIds, claimers);

    assertEq(instance.validSignerCount(), _signerCount, "incorrect valid signer count");
    // owner count should be 1 more than the number of valid signers since the hsg instance is still an owner
    assertEq(safe.getOwners().length, _signerCount + 1, "should be 1 more than the number of valid signers");
  }

  function test_revert_notClaimableFor(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true and then undo it
    vm.prank(owner);
    instance.setClaimableFor(true);
    vm.prank(owner);
    instance.setClaimableFor(false);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    instance.claimSignersFor(hatIds, claimers);

    assertEq(instance.validSignerCount(), 0, "incorrect valid signer count");
    assertEq(safe.getOwners().length, 1, "incorrect owner count");
  }

  function test_revert_invalidSignerHat(uint256 _signerCount) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);
    uint256 invalidSignerHat = signerHat + 1;

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      _setSignerValidity(signerAddresses[i], signerHat, true);
    }

    // set the claimable for to true
    vm.prank(owner);
    instance.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = invalidSignerHat;
    }

    vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.InvalidSignerHat.selector, invalidSignerHat));
    instance.claimSignersFor(hatIds, claimers);
  }

  function test_revert_invalidSigner(uint256 _signerCount, uint256 _invalidSignerIndex) public {
    _signerCount = bound(_signerCount, 1, signerAddresses.length);
    _invalidSignerIndex = bound(_invalidSignerIndex, 0, _signerCount - 1);

    // set up signer validity
    for (uint256 i; i < _signerCount; ++i) {
      if (i == _invalidSignerIndex) {
        _setSignerValidity(signerAddresses[i], signerHat, false);
      } else {
        _setSignerValidity(signerAddresses[i], signerHat, true);
      }
    }

    // set the claimable for to true
    vm.prank(owner);
    instance.setClaimableFor(true);

    // create the necessary arrays
    address[] memory claimers = new address[](_signerCount);
    uint256[] memory hatIds = new uint256[](_signerCount);
    for (uint256 i; i < _signerCount; ++i) {
      claimers[i] = signerAddresses[i];
      hatIds[i] = signerHat;
    }

    vm.expectRevert(
      abi.encodeWithSelector(IHatsSignerGate.NotSignerHatWearer.selector, signerAddresses[_invalidSignerIndex])
    );
    instance.claimSignersFor(hatIds, claimers);
  }
}

/// @dev see HatsSignerGate.internals.t.sol:RemovingSignerInternals for tests of internal logic
contract RemovingSigner is WithHSGInstanceTest {
  function test_happy_removeSigner(uint256 _seed) public {
    // get a random signer
    address signer = _getRandomAddress(_seed);
    // get a random valid signer hat
    uint256 signerHat = _getRandomValidSignerHat(_seed);

    // set the signer hat validity
    _setSignerValidity(signer, signerHat, true);

    // claim the signer
    vm.prank(signer);
    instance.claimSigner(signerHat);

    // signer loses their hat
    _setSignerValidity(signer, signerHat, false);

    // remove the signer
    instance.removeSigner(signer);

    assertFalse(safe.isOwner(signer), "the signer should no longer be an owner");
    assertFalse(instance.isValidSigner(signer), "the signer should no longer be a valid signer");
    assertEq(instance.registeredSignerHats(signer), 0, "the signer should no longer be registered for any hats");
  }

  function test_revert_stillWearsSignerHat(uint256 _seed) public {
    // get a random signer
    address signer = _getRandomAddress(_seed);
    // get a random valid signer hat
    uint256 signerHat = _getRandomValidSignerHat(_seed);

    // set the signer hat validity
    _setSignerValidity(signer, signerHat, true);

    // claim the signer
    vm.prank(signer);
    instance.claimSigner(signerHat);

    // remove the signer should revert
    vm.expectRevert(IHatsSignerGate.StillWearsSignerHat.selector);
    instance.removeSigner(signer);

    assertTrue(safe.isOwner(signer), "the signer should still be an owner");
    assertTrue(instance.isValidSigner(signer), "the signer should still be a valid signer");
    assertEq(instance.registeredSignerHats(signer), signerHat, "the signer should still be registered for their hat");
  }
}

contract Locking is WithHSGInstanceTest {
  function test_happy_lock() public isLocked(false) callerIsOwner(true) {
    vm.expectEmit();
    emit IHatsSignerGate.HSGLocked();
    vm.prank(caller);
    instance.lock();

    assertEq(instance.locked(), true, "HSG should be locked");
  }

  function test_revert_locked(bool _callerIsOwner) public isLocked(true) callerIsOwner(_callerIsOwner) {
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.lock();

    assertEq(instance.locked(), true, "HSG should still be locked");
  }

  function test_revert_notOwner() public isLocked(false) callerIsOwner(false) {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.lock();

    assertEq(instance.locked(), false, "HSG should still be unlocked");
  }
}

contract SettingOwnerHat is WithHSGInstanceTest {
  function test_fuzz_happy_setOwnerHat(uint256 _newOwnerHat) public isLocked(false) callerIsOwner(true) {
    vm.expectEmit();
    emit IHatsSignerGate.OwnerHatSet(_newOwnerHat);
    vm.prank(caller);
    instance.setOwnerHat(_newOwnerHat);

    assertEq(instance.ownerHat(), _newOwnerHat, "owner hat should be new");
  }

  function test_fuzz_revert_locked(uint256 _newOwnerHat, bool _callerIsOwner)
    public
    isLocked(true)
    callerIsOwner(_callerIsOwner)
  {
    uint256 oldOwnerHat = instance.ownerHat();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.setOwnerHat(_newOwnerHat);

    assertEq(instance.ownerHat(), oldOwnerHat, "owner hat should be old");
  }

  function test_fuzz_revert_notOwner(uint256 _newOwnerHat) public isLocked(false) callerIsOwner(false) {
    uint256 oldOwnerHat = instance.ownerHat();

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.setOwnerHat(_newOwnerHat);

    assertEq(instance.ownerHat(), oldOwnerHat, "owner hat should be old");
  }
}

contract AddingSignerHats is WithHSGInstanceTest {
  function test_fuzz_happy_addSignerHats(uint8 _numHats) public isLocked(false) callerIsOwner(true) {
    uint256[] memory signerHats = _getRandomSignerHats(_numHats);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(signerHats);
    vm.prank(caller);
    instance.addSignerHats(signerHats);

    assertValidSignerHats(signerHats);
  }

  function test_fuzz_revert_locked(uint8 _numHats, bool _callerIsOwner)
    public
    isLocked(true)
    callerIsOwner(_callerIsOwner)
  {
    uint256[] memory signerHats = _getRandomSignerHats(_numHats);

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.addSignerHats(signerHats);
  }

  function test_fuzz_revert_notOwner(uint8 _numHats) public isLocked(false) callerIsOwner(false) {
    uint256[] memory signerHats = _getRandomSignerHats(_numHats);

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.addSignerHats(signerHats);
  }
}

/// @dev see HatsSignerGate.internals.t.sol:OwnerSettingsInternals for threshold config validation tests
contract SettingThresholdConfig is WithHSGInstanceTest {
  function test_fuzz_happy_setThresholdConfig(uint8 _type, uint8 _min, uint16 _target)
    public
    isLocked(false)
    callerIsOwner(true)
  {
    // create a valid threshold config
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    vm.expectEmit();
    emit IHatsSignerGate.ThresholdConfigSet(config);
    vm.prank(caller);
    instance.setThresholdConfig(config);
  }

  function test_fuzz_revert_locked(uint8 _type, uint8 _min, uint16 _target, bool _callerIsOwner)
    public
    isLocked(true)
    callerIsOwner(_callerIsOwner)
  {
    // create a valid threshold config
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.setThresholdConfig(config);
  }

  function test_fuzz_revert_notOwner(uint8 _type, uint8 _min, uint16 _target)
    public
    isLocked(false)
    callerIsOwner(false)
  {
    // create a valid threshold config
    IHatsSignerGate.TargetThresholdType thresholdType = IHatsSignerGate.TargetThresholdType(bound(_type, 0, 1));
    IHatsSignerGate.ThresholdConfig memory config = _createValidThresholdConfig(thresholdType, _min, _target);

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.setThresholdConfig(config);
  }
}

contract SettingClaimableFor is WithHSGInstanceTest {
  function test_fuzz_happy_setClaimableFor(bool _claimableFor) public isLocked(false) callerIsOwner(true) {
    vm.expectEmit();
    emit IHatsSignerGate.ClaimableForSet(_claimableFor);
    vm.prank(caller);
    instance.setClaimableFor(_claimableFor);

    assertEq(instance.claimableFor(), _claimableFor, "claimableFor should be new");
  }

  function test_fuzz_revert_locked(bool _claimableFor, bool _callerIsOwner)
    public
    isLocked(true)
    callerIsOwner(_callerIsOwner)
  {
    bool oldClaimableFor = instance.claimableFor();

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.setClaimableFor(_claimableFor);

    assertEq(instance.claimableFor(), oldClaimableFor, "claimableFor should be old");
  }

  function test_fuzz_revert_notOwner(bool _claimableFor) public isLocked(false) callerIsOwner(false) {
    bool oldClaimableFor = instance.claimableFor();

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.setClaimableFor(_claimableFor);

    assertEq(instance.claimableFor(), oldClaimableFor, "claimableFor should be old");
  }
}

contract DetachingHSG is WithHSGInstanceTest {
  function test_happy_detachHSG() public isLocked(false) callerIsOwner(true) {
    vm.expectEmit();
    emit IHatsSignerGate.Detached();
    vm.prank(caller);
    instance.detachHSG();

    assertFalse(safe.isModuleEnabled(address(instance)), "HSG should not be a module");
    assertEq(_getSafeGuard(address(safe)), address(0), "HSG should not be a guard");
  }

  function test_revert_locked(bool _callerIsOwner) public isLocked(true) callerIsOwner(_callerIsOwner) {
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.detachHSG();

    assertTrue(safe.isModuleEnabled(address(instance)), "HSG should still be a module");
    assertEq(_getSafeGuard(address(safe)), (address(instance)), "HSG should still be a guard");
  }

  function test_revert_notOwner() public isLocked(false) callerIsOwner(false) {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.detachHSG();

    assertTrue(safe.isModuleEnabled(address(instance)), "HSG should still be a module");
    assertEq(_getSafeGuard(address(safe)), (address(instance)), "HSG should still be a guard");
  }
}

contract MigratingToNewHSG is WithHSGInstanceTest {
  HatsSignerGate newHSG;

  function setUp() public override {
    super.setUp();

    // create the instance deployer
    DeployInstance instanceDeployer = new DeployInstance();

    // set up the deployment with the same parameters as the existing HSG (except for the nonce)
    instanceDeployer.prepare1(
      address(implementationHSG),
      ownerHat,
      signerHats,
      thresholdConfig,
      address(safe),
      false,
      false,
      address(0), // no guard
      new address[](0) // no modules
    );
    instanceDeployer.prepare2(true, 1);

    // deploy the instance
    newHSG = instanceDeployer.run();
  }

  function test_happy_noSignersToMigrate() public isLocked(false) callerIsOwner(true) {
    vm.expectEmit();
    emit IHatsSignerGate.Migrated(address(newHSG));
    vm.prank(caller);
    instance.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));

    assertEq(_getSafeGuard(address(safe)), address(newHSG), "guard should be the new HSG");
    assertFalse(safe.isModuleEnabled(address(instance)), "old HSG should be disabled as module");
    assertTrue(safe.isModuleEnabled(address(newHSG)), "new HSG should be enabled as module");
  }

  function test_happy_signersToMigrate(uint256 _count) public isLocked(false) callerIsOwner(true) {
    uint256 count = bound(_count, 1, signerAddresses.length);
    // add some signers to the existing HSG
    _addSignersSameHat(count, signerHat);

    // set the claimable for to true for the new HSG
    vm.prank(owner);
    newHSG.setClaimableFor(true);

    // create the migration arrays
    uint256[] memory hatIdsToMigrate = new uint256[](count);
    address[] memory signersToMigrate = new address[](count);
    for (uint256 i; i < count; ++i) {
      hatIdsToMigrate[i] = signerHat;
      signersToMigrate[i] = signerAddresses[i];
    }

    vm.expectEmit();
    emit IHatsSignerGate.Migrated(address(newHSG));
    vm.prank(caller);
    instance.migrateToNewHSG(address(newHSG), hatIdsToMigrate, signersToMigrate);

    assertEq(_getSafeGuard(address(safe)), address(newHSG), "guard should be the new HSG");
    assertFalse(safe.isModuleEnabled(address(instance)), "old HSG should be disabled as module");
    assertTrue(safe.isModuleEnabled(address(newHSG)), "new HSG should be enabled as module");

    // check that the signers are now in the new HSG
    for (uint256 i; i < count; ++i) {
      assertTrue(newHSG.isValidSigner(signersToMigrate[i]), "signer should be in the new HSG");
    }
    assertEq(newHSG.validSignerCount(), count, "valid signer count should be correct");
  }

  function test_revert_notClaimableFor_signersToMigrate(uint256 _count) public isLocked(false) callerIsOwner(true) {
    uint256 count = bound(_count, 1, signerAddresses.length);
    // add some signers to the existing HSG
    _addSignersSameHat(count, signerHat);

    // don't set the claimable for to true for the new HSG

    // create the migration arrays
    uint256[] memory hatIdsToMigrate = new uint256[](count);
    address[] memory signersToMigrate = new address[](count);
    for (uint256 i; i < count; ++i) {
      hatIdsToMigrate[i] = signerHat;
      signersToMigrate[i] = signerAddresses[i];
    }

    vm.expectRevert(IHatsSignerGate.NotClaimableFor.selector);
    vm.prank(caller);
    instance.migrateToNewHSG(address(newHSG), hatIdsToMigrate, signersToMigrate);

    assertEq(_getSafeGuard(address(safe)), address(instance), "guard should be the old HSG");
    assertTrue(safe.isModuleEnabled(address(instance)), "old HSG should be enabled as module");
    assertFalse(safe.isModuleEnabled(address(newHSG)), "new HSG should not be enabled as module");

    // check that the signers are now in the new HSG
    for (uint256 i; i < count; ++i) {
      assertFalse(newHSG.isValidSigner(signersToMigrate[i]), "signer should not be in the new HSG");
    }
    assertEq(newHSG.validSignerCount(), 0, "valid signer count should be 0");
  }

  function test_revert_nonOwner() public isLocked(false) callerIsOwner(false) {
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));

    assertEq(_getSafeGuard(address(safe)), address(instance), "guard should be the old HSG");
    assertTrue(safe.isModuleEnabled(address(instance)), "old HSG should be enabled as module");
    assertFalse(safe.isModuleEnabled(address(newHSG)), "new HSG should not be enabled as module");
  }

  function test_revert_locked() public isLocked(true) callerIsOwner(true) {
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.migrateToNewHSG(address(newHSG), new uint256[](0), new address[](0));

    assertEq(_getSafeGuard(address(safe)), address(instance), "guard should be the old HSG");
    assertTrue(safe.isModuleEnabled(address(instance)), "old HSG should be enabled as module");
    assertFalse(safe.isModuleEnabled(address(newHSG)), "new HSG should not be enabled as module");
  }
}

contract EnablingDelegatecallTarget is WithHSGInstanceTest {
  function test_fuzz_happy_enableDelegatecallTarget(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address target = _getRandomAddress(_seed);

    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, true);
    vm.prank(caller);
    instance.enableDelegatecallTarget(target);

    assertTrue(instance.enabledDelegatecallTargets(target), "new target should be enabled");
  }

  function test_fuzz_revert_locked(uint256 _seed, bool _callerIsOwner)
    public
    isLocked(true)
    callerIsOwner(_callerIsOwner)
  {
    address target = _getRandomAddress(_seed);

    bool wasEnabled = instance.enabledDelegatecallTargets(target);

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.enableDelegatecallTarget(target);

    assertEq(instance.enabledDelegatecallTargets(target), wasEnabled, "target enabled state should not change");
  }

  function test_fuzz_revert_notOwner(uint256 _seed) public isLocked(false) callerIsOwner(false) {
    address target = _getRandomAddress(_seed);

    bool wasEnabled = instance.enabledDelegatecallTargets(target);

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.enableDelegatecallTarget(target);

    assertEq(instance.enabledDelegatecallTargets(target), wasEnabled, "target enabled state should not change");
  }
}

contract DisablingDelegatecallTarget is WithHSGInstanceTest {
  function test_fuzz_happy_disableDelegatecallTarget(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address target = _getRandomAddress(_seed);

    // enable the target first
    vm.prank(owner);
    instance.enableDelegatecallTarget(target);

    // expect the target to be disabled
    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, false);
    vm.prank(caller);
    instance.disableDelegatecallTarget(target);

    assertFalse(instance.enabledDelegatecallTargets(target), "target should be disabled");
  }

  function test_revert_locked(uint256 _seed, bool _callerIsOwner) public isLocked(false) callerIsOwner(_callerIsOwner) {
    address target = _getRandomAddress(_seed);

    // enable the target first and then lock the HSG
    vm.startPrank(owner);
    instance.enableDelegatecallTarget(target);
    instance.lock();
    vm.stopPrank();
    // expect the target to be disabled
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.disableDelegatecallTarget(target);

    assertTrue(instance.enabledDelegatecallTargets(target), "target should still be enabled");
  }

  function test_revert_notOwner(uint256 _seed) public isLocked(false) callerIsOwner(false) {
    address target = _getRandomAddress(_seed);

    // enable the target first
    vm.prank(owner);
    instance.enableDelegatecallTarget(target);

    // expect the target to be disabled
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.disableDelegatecallTarget(target);

    assertTrue(instance.enabledDelegatecallTargets(target), "target should still be enabled");
  }
}

/// @dev Tests for internal logic of Modifier.enableModule function can be found here:
/// https://github.com/gnosisguild/zodiac/blob/18b7575bb342424537883f7ebe0a94cd7f3ec4f6/test/03_Modifier.spec.ts
contract EnablingModule is WithHSGInstanceTest {
  function test_happy_enableModule(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address module = _getRandomAddress(_seed);

    vm.expectEmit();
    emit IAvatar.EnabledModule(module);
    vm.prank(caller);
    instance.enableModule(module);

    assertTrue(instance.isModuleEnabled(module), "module should be enabled");
  }

  function test_revert_locked(uint256 _seed, bool _callerIsOwner) public isLocked(true) callerIsOwner(_callerIsOwner) {
    address module = _getRandomAddress(_seed);

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.enableModule(module);

    assertFalse(instance.isModuleEnabled(module), "module should not be enabled");
  }

  function test_fuzz_revert_notOwner(uint256 _seed) public isLocked(false) callerIsOwner(false) {
    address module = _getRandomAddress(_seed);

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.enableModule(module);

    assertFalse(instance.isModuleEnabled(module), "module should not be enabled");
  }
}

/// @dev Tests for internal logic of Modifier.disableModule function can be found here:
/// https://github.com/gnosisguild/zodiac/blob/18b7575bb342424537883f7ebe0a94cd7f3ec4f6/test/03_Modifier.spec.ts
contract DisablingModule is WithHSGInstanceTest {
  function test_happy_disableModule(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address module = _getRandomAddress(_seed);

    // enable the module first
    vm.prank(owner);
    instance.enableModule(module);

    // expect the module to be disabled
    vm.expectEmit();
    emit IAvatar.DisabledModule(module);
    vm.prank(caller);
    instance.disableModule({ prevModule: SENTINELS, module: module });

    assertFalse(instance.isModuleEnabled(module), "module should be disabled");
  }

  function test_happy_disableModule_twoModules(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address module1 = _getRandomAddress(_seed);
    address module2 = address(uint160(uint256(keccak256(abi.encode(_getRandomAddress(_seed))))));

    // enable both modules
    vm.startPrank(owner);
    instance.enableModule(module1);
    instance.enableModule(module2);
    vm.stopPrank();

    // disable the first module
    vm.expectEmit();
    emit IAvatar.DisabledModule(module1);
    vm.prank(caller);
    instance.disableModule({ prevModule: module2, module: module1 });

    assertFalse(instance.isModuleEnabled(module1), "module1 should be disabled");
  }

  function test_revert_locked(uint256 _seed, bool _callerIsOwner) public isLocked(false) callerIsOwner(_callerIsOwner) {
    address module = _getRandomAddress(_seed);

    // enable the module first, then lock the HSG
    vm.startPrank(owner);
    instance.enableModule(module);
    instance.lock();
    vm.stopPrank();

    // expect the module to not be disabled
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.disableModule({ prevModule: SENTINELS, module: module });

    assertTrue(instance.isModuleEnabled(module), "module should still be enabled");
  }

  function test_revert_notOwner(uint256 _seed) public isLocked(false) callerIsOwner(false) {
    address module = _getRandomAddress(_seed);

    // enable the module first
    vm.prank(owner);
    instance.enableModule(module);

    // expect the module to not be disabled
    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.disableModule({ prevModule: SENTINELS, module: module });

    assertTrue(instance.isModuleEnabled(module), "module should still be enabled");
  }
}

/// @dev Tests for internal logic of Guardable.setGuard function can be found here:
/// https://github.com/gnosisguild/zodiac/blob/18b7575bb342424537883f7ebe0a94cd7f3ec4f6/test/04_Guardable.spec.ts
contract SettingGuard is WithHSGInstanceTest {
  function test_happy_setGuard(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    // get a random guard
    address newGuard = _getRandomGuard(_seed);

    // expect the guard to be set
    vm.expectEmit();
    emit GuardableUnowned.ChangedGuard(newGuard);
    vm.prank(caller);
    instance.setGuard(newGuard);

    assertEq(instance.getGuard(), newGuard, "guard should be new");

    // now remove the guard
    vm.expectEmit();
    emit GuardableUnowned.ChangedGuard(address(0));
    vm.prank(caller);
    instance.setGuard(address(0));

    assertEq(instance.getGuard(), address(0), "guard should be removed");
  }

  function test_revert_notIERC165Compliant(uint256 _seed) public isLocked(false) callerIsOwner(true) {
    address newGuard = _getRandomAddress(_seed);

    vm.expectRevert();
    vm.prank(caller);
    instance.setGuard(newGuard);

    assertEq(instance.getGuard(), address(0), "guard should not be set");
  }

  function test_revert_locked(uint256 _seed, bool _callerIsOwner) public isLocked(true) callerIsOwner(_callerIsOwner) {
    address newGuard = _getRandomGuard(_seed);

    vm.expectRevert(IHatsSignerGate.Locked.selector);
    vm.prank(caller);
    instance.setGuard(newGuard);

    assertEq(instance.getGuard(), address(0), "guard should not be set");
  }

  function test_revert_notOwner(uint256 _seed) public isLocked(false) callerIsOwner(false) {
    address newGuard = _getRandomGuard(_seed);

    vm.expectRevert(IHatsSignerGate.NotOwnerHatWearer.selector);
    vm.prank(caller);
    instance.setGuard(newGuard);

    assertEq(instance.getGuard(), address(0), "guard should not be set");
  }
}

/// @dev These tests use the harness to access the transient state variables set within checkTransaction. Most of the
/// tests call harness.exposed_checkTransaction, which wraps instance.checkTransaction and stores the transient state in
/// persistent storage for access in tests.
contract CheckTransaction is WithHSGHarnessInstanceTest {
  uint256 public simulatedInitialNonce;

  function setUp() public override {
    super.setUp();

    // Execute an empty transaction from the safe to set the nonce to force the safe's nonce to increment. This is
    // necessary to simulate the conditions under which HSG.checkTransaction is called in practice, ie just after the
    // nonce has incremented. This also adds two signers.
    _executeEmptyCallFromSafe(2, address(org));

    assertGt(safe.nonce(), 0, "safe nonce should gt 0");

    simulatedInitialNonce = safe.nonce() - 1;
  }

  function test_happy_checkTransaction_callToNonSafe(uint256 _seed)
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    address target = _getRandomAddress(_seed);
    vm.assume(target != address(safe));

    // get the signatures for an empty delegatecall to the target
    // we use contract signatures here to avoid dealing with txhash decoding, which requires the nonce to be correct,
    // which its not since we're skipping the safe.execTransaction call that increments it
    bytes memory signatures = _createNContractSigs(2);

    vm.prank(caller);
    harness.exposed_checkTransaction(
      target, 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signatures, address(0)
    );

    _assertTransientStateVariables({
      _operation: Enum.Operation.Call, // this is a call
      _existingOwnersHash: bytes32(0), // empty because call
      _existingThreshold: 0, // empty because call
      _existingFallbackHandler: address(0), // empty because call
      _inSafeExecTransaction: true,
      _inModuleExecTransaction: false, // not a module tx
      _initialNonce: simulatedInitialNonce,
      _checkTransactionCounter: 1
    });
  }

  function test_revert_notCalledFromSafe()
    public
    callerIsSafe(false)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    vm.expectRevert(IHatsSignerGate.NotCalledFromSafe.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(0), 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_guardReverts()
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // add a test guard
    vm.prank(owner);
    harness.setGuard(address(tstGuard));

    // mock the guard's checkTransaction to revert
    vm.mockCallRevert(address(tstGuard), abi.encodeWithSelector(tstGuard.checkTransaction.selector), "");

    // call to checkTransaction should revert
    vm.expectRevert();
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(0), 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_delegatecallTargetEnabled()
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // enable a delegatecall target
    address target = defaultDelegatecallTargets[0];
    vm.prank(owner);
    harness.enableDelegatecallTarget(target);

    // get the signatures for an empty delegatecall to the target
    // we use contract signatures here to avoid dealing with txhash decoding, which requires the nonce to be correct,
    // which its not since we're skipping the safe.execTransaction call that increments it
    bytes memory signatures = _createNContractSigs(2);

    uint256 expectedThreshold = safe.getThreshold();
    address expectedFallbackHandler = SafeManagerLib.getSafeFallbackHandler(safe);
    bytes32 expectedOwnersHash = keccak256(abi.encode(safe.getOwners()));

    vm.prank(caller);
    harness.exposed_checkTransaction(
      target, 0, new bytes(0), Enum.Operation.DelegateCall, 0, 0, 0, address(0), payable(0), signatures, address(0)
    );

    // transient state should be populated
    _assertTransientStateVariables({
      _operation: Enum.Operation.DelegateCall, // delegatecall
      _existingOwnersHash: expectedOwnersHash, // populated since delegatecall
      _existingThreshold: expectedThreshold, // populated since delegatecall
      _existingFallbackHandler: expectedFallbackHandler, // populated since delegatecall
      _inSafeExecTransaction: true,
      _inModuleExecTransaction: false, // not a module tx
      _initialNonce: simulatedInitialNonce,
      _checkTransactionCounter: 1
    });
  }

  function test_revert_delegatecallTargetNotEnabled()
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // expect the checkTransaction to revert
    vm.expectRevert(IHatsSignerGate.DelegatecallTargetNotEnabled.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(0),
      0,
      new bytes(0),
      Enum.Operation.DelegateCall,
      0,
      0,
      0,
      address(0),
      payable(0),
      new bytes(0),
      address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_cannotCallSafe()
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    vm.expectRevert(IHatsSignerGate.CannotCallSafe.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(safe), 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_thresholdTooLow(uint8 _operation)
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // bound the arg
    Enum.Operation operation = Enum.Operation(bound(_operation, 0, 1));

    // remove one signer to make the threshold too low
    _setSignerValidity(signerAddresses[0], signerHat, false);
    vm.prank(owner);
    harness.removeSigner(signerAddresses[0]);

    address target;

    // enable a delegatecall target if we're checking delegatecalls
    if (operation == Enum.Operation.DelegateCall) {
      target = defaultDelegatecallTargets[0];
      vm.prank(owner);
      harness.enableDelegatecallTarget(target);
    } else {
      target = _getRandomAddress();
    }

    // expect the checkTransaction to revert
    vm.expectRevert(IHatsSignerGate.ThresholdTooLow.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      target, 0, new bytes(0), operation, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_insufficientValidSignatures(uint8 _operation)
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // bound the arg
    Enum.Operation operation = Enum.Operation(bound(_operation, 0, 1));

    // invalidate one signer but don't remove them
    _setSignerValidity(signerAddresses[0], signerHat, false);

    address target;

    // enable a delegatecall target if we're checking delegatecalls
    if (operation == Enum.Operation.DelegateCall) {
      target = defaultDelegatecallTargets[0];
      vm.prank(owner);
      harness.enableDelegatecallTarget(target);
    } else {
      target = _getRandomAddress();
    }

    // create two contract signatures
    bytes memory signatures = _createNContractSigs(2);

    // expect the checkTransaction to revert
    vm.expectRevert(IHatsSignerGate.InsufficientValidSignatures.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      target, 0, new bytes(0), operation, 0, 0, 0, address(0), payable(0), signatures, address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_inSafeExecTransaction(bool _inModuleExecTransaction)
    public
    callerIsSafe(true)
    inSafeExecTransaction(true)
    inModuleExecTransaction(_inModuleExecTransaction)
  {
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(safe), 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_inModuleExecTransaction(bool _inSafeExecTransaction)
    public
    callerIsSafe(true)
    inSafeExecTransaction(_inSafeExecTransaction)
    inModuleExecTransaction(true)
  {
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    vm.prank(caller);
    harness.exposed_checkTransaction(
      address(safe), 0, new bytes(0), Enum.Operation.Call, 0, 0, 0, address(0), payable(0), new bytes(0), address(0)
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_noReentryAllowed()
    public
    callerIsSafe(true)
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // first craft a dummy/empty tx to pass to checkTransaction
    bytes32 dummyTxHash = safe.getTransactionHash(
      address(this), // send 0 eth to this contract
      0,
      hex"00",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      address(0),
      safe.nonce()
    );

    bytes memory dummyTxSigs = _createNSigsForTx(dummyTxHash, 2);

    // create the calldata for a call back to checkTransaction
    bytes memory reentryCall = abi.encodeWithSelector(
      HatsSignerGate.checkTransaction.selector,
      address(0),
      0,
      "",
      Enum.Operation.Call,
      0,
      0,
      0,
      address(0),
      payable(0),
      dummyTxSigs,
      address(this)
    );

    // get the txHash for the reentry call
    bytes32 txHash = safe.getTransactionHash(
      address(harness), 0, reentryCall, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), safe.nonce()
    );

    // create 2 valid signatures for the txHash
    bytes memory signatures = _createNSigsForTx(txHash, 2);

    // expect the checkTransaction to revert. HSG will throw IHatsSignerGate.NoReentryAllowed, but the Safe will catch
    // it and re-throw "GS013"
    vm.expectRevert("GS013");
    safe.execTransaction(
      address(harness), 0, reentryCall, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signatures
    );

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }
}

/// @dev These tests use the harness to ensure that the transient state that would normally be set by checkTransaction
/// is available in checkAfterExecution.
/// Most of these tests call harness.exposed_checkAfterExecution to accomplish this.
/// Additonally, these tests do not cover the internal Safe state checks. See
/// HatsSignerGate.internals.t.sol:TransactionValidationInternals for comprehensive tests of that logic.
contract CheckAfterExecution is WithHSGHarnessInstanceTest {
  function test_happy_checkAfterExecution(bytes32 _txHash, bool _success)
    public
    inSafeExecTransaction(true)
    inModuleExecTransaction(false)
  {
    // call to checkAfterExecution should not revert
    harness.exposed_checkAfterExecution(_txHash, _success);

    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_guardReverts(bytes32 _txHash, bool _success)
    public
    inSafeExecTransaction(true)
    inModuleExecTransaction(false)
  {
    // add a test guard
    vm.prank(owner);
    harness.setGuard(address(tstGuard));

    // mock the guard's checkTransaction to revert
    vm.mockCallRevert(address(tstGuard), abi.encodeWithSelector(tstGuard.checkAfterExecution.selector), "");

    // call to checkAfterExecution should revert
    vm.expectRevert();
    harness.exposed_checkAfterExecution(_txHash, _success);

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_notInSafeExecTransaction(bytes32 _txHash, bool _success)
    public
    inSafeExecTransaction(false)
    inModuleExecTransaction(false)
  {
    // should revert because we are not inside a Safe execTransaction call
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    harness.exposed_checkAfterExecution(_txHash, _success);

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }

  function test_revert_inModuleExecTransaction(bytes32 _txHash, bool _success)
    public
    inSafeExecTransaction(true)
    inModuleExecTransaction(true)
  {
    // should revert because we are not inside a Safe execTransaction call
    vm.expectRevert(IHatsSignerGate.NoReentryAllowed.selector);
    harness.exposed_checkAfterExecution(_txHash, _success);

    // transient state should be cleared after revert
    _assertTransientStateVariables({
      _operation: Enum.Operation(uint8(0)),
      _existingOwnersHash: bytes32(0),
      _existingThreshold: 0,
      _existingFallbackHandler: address(0),
      _inSafeExecTransaction: false,
      _inModuleExecTransaction: false,
      _initialNonce: 0,
      _checkTransactionCounter: 0
    });
  }
}

contract Views is WithHSGInstanceTest {
  function test_fuzz_validSignerCount(uint256 _count) public {
    uint256 count = bound(_count, 0, signerAddresses.length);
    _addSignersSameHat(count, signerHat);

    assertEq(instance.validSignerCount(), count, "valid signer count should be correct");
  }

  function test_fuzz_canAttachToSafe() public {
    // deploy an instance with
    // deploy a new safe
    ISafe newSafe = _deploySafe(signerAddresses, 1, 1);

    // the new safe should be attachable since it has no modules
    assertTrue(instance.canAttachToSafe(newSafe), "should be attachable");
  }

  function test_false_canAttachToSafe(uint256 _seed) public {
    // deploy an instance with
    // deploy a new safe
    ISafe newSafe = _deploySafe(signerAddresses, 1, 1);

    // enable a random module on the new safe
    address module = _getRandomAddress(_seed);
    vm.prank(address(newSafe));
    newSafe.enableModule(module);

    // the new safe should not be attachable since it has a module
    assertFalse(instance.canAttachToSafe(newSafe), "should not be attachable");
  }
}

contract HSGGuarding is WithHSGInstanceTest {
  uint256 public disallowedValue = 1337;
  uint256 public goodValue = 9_000_000_000;
  address public recipient = makeAddr("recipient");
  uint256 public signerCount = 2;

  function setUp() public override {
    super.setUp();

    // set it on our hsg instance
    vm.prank(owner);
    instance.setGuard(address(tstGuard));
    assertEq(instance.getGuard(), address(tstGuard), "guard should be tstGuard");

    // deal the safe some eth
    deal(address(safe), 1 ether);

    // add signerCount number of signers
    _addSignersSameHat(signerCount, signerHat);

    address[] memory owners = safe.getOwners();
    assertEq(owners.length, signerCount, "owners should be signerCount");
  }

  /// @dev a successful transaction should hit the tstGuard's checkTransaction and checkAfterExecution funcs
  function test_executed() public {
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = goodValue;
    uint256 postValue = preValue - transferValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the `sender` param to be address(0) because the sender param from hsg.checkTransaction is empty
    vm.expectEmit();
    emit TestGuard.PreChecked(address(0));
    vm.expectEmit();
    emit TestGuard.PostChecked(true);

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx succeeded by checking ETH balance changes
    assertEq(address(safe).balance, postValue);
    assertEq(recipient.balance, transferValue);
    assertEq(safe.nonce(), preNonce + 1);
  }

  // the test guard should revert in checkTransaction
  function test_revert_checkTransaction() public {
    // we make this happen by using a bad value in the safe.execTransaction call
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = disallowedValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the test guard to revert in checkTransaction
    vm.expectRevert("Cannot send 1337");

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }

  // the test guard should revert in checkAfterExecution
  function test_revert_checkAfterExecution() public {
    // we make this happen by setting the test guard to disallow execution
    tstGuard.disallowExecution();

    // craft a basic eth transfer tx
    uint256 preNonce = safe.nonce();
    uint256 preValue = address(safe).balance;
    uint256 transferValue = goodValue;

    // create the tx
    bytes32 txHash = _getTxHash(recipient, transferValue, Enum.Operation.Call, hex"00", safe);

    // have 3 signers sign it
    bytes memory signatures = _createNSigsForTx(txHash, signerCount);

    // we expect the test guard to revert in checkTransaction
    vm.expectRevert("Reverted in checkAfterExecution");

    // have one of the signers submit/exec the tx
    vm.prank(signerAddresses[0]);
    safe.execTransaction(
      recipient,
      transferValue,
      hex"00",
      Enum.Operation.Call,
      // not using the refunder
      0,
      0,
      0,
      address(0),
      payable(address(0)),
      signatures
    );

    // confirm the tx did not succeed by checking ETH balance changes
    assertEq(address(safe).balance, preValue);
    assertEq(recipient.balance, 0);
    assertEq(safe.nonce(), preNonce);
  }
}
