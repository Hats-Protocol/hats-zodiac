// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {
    TestSuite,
    HatsSignerGate,
    HatsSignerGateFactory,
    GnosisSafeProxyFactory,
    ModuleProxyFactory,
    GnosisSafe
} from "./TestSuite.sol";
// import "../src/HSGLib.sol";

contract HatsSignerGateFactoryTest is TestSuite {
    error NoOtherModulesAllowed();

    function testDeployFactory() public {
        assertEq(factory.version(), version, "version");
        assertEq(factory.hatsSignerGateSingleton(), address(singletonHatsSignerGate), "hatsSignerGateSingleton");
        assertEq(address(factory.safeSingleton()), address(singletonSafe), "safeSingleton");
        assertEq(factory.gnosisFallbackLibrary(), gnosisFallbackLibrary, "gnosisFallbackLibrary");
        assertEq(factory.gnosisMultisendLibrary(), gnosisMultisendLibrary, "gnosisMultisendLibrary");
        assertEq(address(factory.gnosisSafeProxyFactory()), address(safeFactory), "gnosisSafeProxyFactory");
    }

    function testDeployHatsSignerGate() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = _deploySafe(initSafeOwners, 1);

        hatsSignerGate = HatsSignerGate(
            factory.deployHatsSignerGate(ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners)
        );

        assertEq(safe.getOwners()[0], address(this), "safe owner");

        assertEq(hatsSignerGate.minThreshold(), minThreshold, "min threshold");
        assertEq(hatsSignerGate.ownerHat(), ownerHat, "owner hat");
        assertEq(hatsSignerGate.getHatsContract(), address(hats), "hats contract");
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold, "target threshold");
        assertEq(address(hatsSignerGate.safe()), address(safe), "safe");
        assertEq(hatsSignerGate.maxSigners(), maxSigners, "max signers");
        assertEq(hatsSignerGate.version(), version, "version");
        assertTrue(hatsSignerGate.isValidSignerHat(2), "valid signer hat");
        assertFalse(hatsSignerGate.isValidSignerHat(3), "invalid signer hat");
    }

    function testDeployHatsSignersGateAndSafe() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        (hatsSignerGate, safe) = _deployHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);

        assertEq(safe.getOwners()[0], address(hatsSignerGate));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
        assertTrue(hatsSignerGate.isValidSignerHat(2));
        assertFalse(hatsSignerGate.isValidSignerHat(3));

        assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));

        assertEq(address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)), address(hatsSignerGate));

        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.getHatsContract(), address(hats));
    }

    function testCannotReinitializeHSGSingleton() public {
        bytes memory initializeParams = abi.encode(
            ownerHat, signerHats, address(safe), address(hats), minThreshold, targetThreshold, maxSigners, version, 0
        );
        vm.expectRevert("Initializable: contract is already initialized");
        singletonHatsSignerGate.setUp(initializeParams);
    }

    function testCannotDeployHSGToSafeWithExistingModules() public {
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe to a signer
        initSafeOwners[0] = address(this);
        safe = _deploySafe(initSafeOwners, 1);

        // add a module
        bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        _executeSafeTxFrom(address(this), addModuleData, safe);

        // attempt to deploy HSG, should revert
        vm.expectRevert(NoOtherModulesAllowed.selector);
        factory.deployHatsSignerGate(ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners);
    }

    function testCanAttachHSGToSafeReturnsFalseWithModule() public {
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = _deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg =
            factory.deployHatsSignerGate(ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners);

        // enable a module
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        _executeSafeTxFrom(address(this), enableModuleData, safe);

        // canAttachHSGToSafe should return false
        assertFalse(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }

    // function testCanAttachHSGToSafeReturnsFalseWithUnsafeSignerCounts() public {
    //     minThreshold = 1;
    //     targetThreshold = 1;
    //     maxSigners = 2;

    //     // deploy a safe
    //     initSafeOwners[0] = signerAddresses[0];
    //     _setSignerValidity(signerAddresses[0], signerHat, true);
    //     safe = _deploySafe(initSafeOwners, 1);

    //     // deploy HSG
    //     HatsSignerGate hsg = HatsSignerGate(
    //         factory.deployHatsSignerGate(ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners)
    //     );

    //     // add 2 owners and make them valid
    //     bytes memory addOwnerData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(2), 1);
    //     _executeSafeTxFrom(signerAddresses[0], addOwnerData, safe);
    //     _setSignerValidity(signerAddresses[1], signerHat, true);

    //     addOwnerData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(3), 1);
    //     _executeSafeTxFrom(signerAddresses[0], addOwnerData, safe);
    //     _setSignerValidity(signerAddresses[2], signerHat, true);

    //     // canAttachHSGToSafe should return false
    //     assertEq(hsg.validSignerCount(), 3, "valid signer count");
    //     assertEq(hsg.maxSigners(), 2, "max signers");
    //     assertFalse(factory.canAttachHSGToSafe(hsg), "should return false with validSignerCount > maxSigners");
    // }

    function testCanAttachHSGToSafeReturnsTrue() public {
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        _setSignerValidity(address(this), signerHat, true);
        safe = _deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg =
            factory.deployHatsSignerGate(ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners);

        // canAttachHSGToSafe should return true
        assertTrue(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }
}
