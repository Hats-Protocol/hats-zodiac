// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGFactoryTestSetup.t.sol";

contract HatsSignerGateFactoryTest is HSGFactoryTestSetup {
    function setUp() public {
        version = "1.0";

        factory = new HatsSignerGateFactory(
            address(singletonHatsSignerGate),
            HATS,
            address(singletonSafe),
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            address(safeFactory),
            address(moduleProxyFactory),
            version
        );
    }

    function testDeployFactory() public {
        assertEq(factory.version(), version);
        assertEq(
            factory.hatsSignerGateSingleton(),
            address(singletonHatsSignerGate)
        );
        assertEq(address(factory.safeSingleton()), address(singletonSafe));
        assertEq(factory.gnosisFallbackLibrary(), gnosisFallbackLibrary);
        assertEq(factory.gnosisMultisendLibrary(), gnosisMultisendLibrary);
        assertEq(
            address(factory.gnosisSafeProxyFactory()),
            address(safeFactory)
        );
    }

    function testDeployHatsSignerGate() public {
        ownerHat = uint256(1);
        signerHat = uint256(2);
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        hatsSignerGate = HatsSignerGate(
            factory.deployHatsSignerGate(
                ownerHat,
                signerHat,
                address(safe),
                minThreshold,
                targetThreshold,
                maxSigners,
                2 // saltNonce
            )
        );

        assertEq(safe.getOwners()[0], address(this));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
    }

    function testDeployHatsSignersGateAndSafe(
        uint256 _ownerHat,
        uint256 _signerHat,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public {
        vm.assume(_ownerHat > 0);
        ownerHat = _ownerHat;

        vm.assume(_signerHat > 0);
        signerHat = _signerHat;

        vm.assume(_maxSigners > 1);
        maxSigners = _maxSigners;

        vm.assume(_targetThreshold <= maxSigners);
        targetThreshold = _targetThreshold;

        vm.assume(_minThreshold <= targetThreshold);
        minThreshold = _minThreshold;

        // address hsg;
        // address safe_;
        (hatsSignerGate, safe) = deployHSGAndSafe(
            ownerHat,
            signerHat,
            minThreshold,
            targetThreshold,
            maxSigners
        );

        // hatsSignerGate = HatsSignerGate(hsg);
        // safe = GnosisSafe(payable(safe_));

        assertEq(safe.getOwners()[0], address(hatsSignerGate));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);

        assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));

        assertEq(
            address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)),
            address(hatsSignerGate)
        );
    }
}
