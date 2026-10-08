// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditAnchor} from "../src/AuditAnchor.sol";

contract AuditAnchorTest is Test {
    AuditAnchor internal anchor;
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    bytes32 internal constant ROOT = keccak256("root-1");

    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        string sourceLabel,
        uint64 recordCount,
        uint64 timestamp,
        address indexed anchoredBy
    );
    event AnchorerSet(address indexed account, bool allowed);

    function setUp() public {
        anchor = new AuditAnchor();
        anchor.setAnchorer(alice, true);
    }

    // ---- access control ----------------------------------------------------
    function test_deployerIsOwner() public view {
        assertEq(anchor.owner(), address(this));
    }

    function test_nonAnchorerCannotAnchor() public {
        vm.prank(bob);
        vm.expectRevert(AuditAnchor.NotAnchorer.selector);
        anchor.anchorBatch(ROOT, "aegis", 10);
    }

    function test_ownerIsNotImplicitlyAnchorer() public {
        vm.expectRevert(AuditAnchor.NotAnchorer.selector);
        anchor.anchorBatch(ROOT, "aegis", 10);
    }

    function test_onlyOwnerCanSetAnchorer() public {
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.NotOwner.selector);
        anchor.setAnchorer(bob, true);
    }

    function test_setAnchorerEmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit AnchorerSet(bob, true);
        anchor.setAnchorer(bob, true);
        assertTrue(anchor.isAnchorer(bob));
    }

    function test_revokedAnchorerCannotAnchor() public {
        anchor.setAnchorer(alice, false);
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.NotAnchorer.selector);
        anchor.anchorBatch(ROOT, "aegis", 10);
    }

    function test_setAnchorerRejectsZeroAddress() public {
        vm.expectRevert(AuditAnchor.ZeroAddress.selector);
        anchor.setAnchorer(address(0), true);
    }

    function test_transferOwnership() public {
        anchor.transferOwnership(bob);
        assertEq(anchor.owner(), bob);
        vm.expectRevert(AuditAnchor.NotOwner.selector);
        anchor.setAnchorer(alice, false);
        vm.prank(bob);
        anchor.setAnchorer(alice, false);
    }

    function test_transferOwnershipRejectsZeroAndNonOwner() public {
        vm.expectRevert(AuditAnchor.ZeroAddress.selector);
        anchor.transferOwnership(address(0));
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.NotOwner.selector);
        anchor.transferOwnership(alice);
    }

    // ---- anchoring + events ------------------------------------------------
    function test_anchorEmitsCorrectEvent() public {
        vm.warp(1_900_000_000);
        vm.expectEmit(true, true, true, true);
        emit BatchAnchored(1, ROOT, "aegis", 10, 1_900_000_000, alice);
        vm.prank(alice);
        uint256 id = anchor.anchorBatch(ROOT, "aegis", 10);
        assertEq(id, 1);
    }

    function test_getBatchReturnsStoredFields() public {
        vm.warp(1_900_000_000);
        vm.roll(777);
        vm.prank(alice);
        uint256 id = anchor.anchorBatch(ROOT, "gauntlet", 42);
        (bytes32 root, bytes32 labelHash, address by, uint64 count, uint64 ts, uint64 blk) = anchor.getBatch(id);
        assertEq(root, ROOT);
        assertEq(labelHash, sha256(bytes("gauntlet")));
        assertEq(by, alice);
        assertEq(count, 42);
        assertEq(ts, 1_900_000_000);
        assertEq(blk, 777);
        assertEq(anchor.batchCount(), 1);
    }

    function test_getBatchUnknownReverts() public {
        vm.expectRevert(AuditAnchor.UnknownBatch.selector);
        anchor.getBatch(0);
        vm.expectRevert(AuditAnchor.UnknownBatch.selector);
        anchor.getBatch(1);
    }

    // ---- duplicate roots ---------------------------------------------------
    function test_duplicateRootsAreAllowedWithDistinctIds() public {
        vm.startPrank(alice);
        uint256 a = anchor.anchorBatch(ROOT, "aegis", 5);
        uint256 b = anchor.anchorBatch(ROOT, "aegis", 5);
        vm.stopPrank();
        assertEq(a, 1);
        assertEq(b, 2);
        (bytes32 r1,,,,,) = anchor.getBatch(a);
        (bytes32 r2,,,,,) = anchor.getBatch(b);
        assertEq(r1, r2);
    }

    // ---- input validation --------------------------------------------------
    function test_zeroRootReverts() public {
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.ZeroRoot.selector);
        anchor.anchorBatch(bytes32(0), "aegis", 1);
    }

    function test_emptyBatchReverts() public {
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.EmptyBatch.selector);
        anchor.anchorBatch(ROOT, "aegis", 0);
    }

    function test_labelTooLongReverts() public {
        string memory longLabel = "01234567890123456789012345678901234567890123456789012345678901234"; // 65 bytes
        vm.prank(alice);
        vm.expectRevert(AuditAnchor.LabelTooLong.selector);
        anchor.anchorBatch(ROOT, longLabel, 1);
    }

    function test_maxLengthLabelAccepted() public {
        string memory label = "0123456789012345678901234567890123456789012345678901234567890123"; // 64 bytes
        vm.prank(alice);
        anchor.anchorBatch(ROOT, label, 1);
    }

    // ---- gas ---------------------------------------------------------------
    /// Gas snapshot guard: a first anchor writes four storage slots and one event. If this
    /// ceiling is exceeded the contract got meaningfully more expensive.
    function test_gasSnapshot_firstAnchorUnderCeiling() public {
        vm.prank(alice);
        uint256 before = gasleft();
        anchor.anchorBatch(ROOT, "synthetic-aegis", 100);
        uint256 used = before - gasleft();
        emit log_named_uint("gas for anchorBatch (first call)", used);
        assertLt(used, 200_000);
    }

    /// The headline property: cost does not depend on how many records the root covers.
    function test_gasIsConstantAcrossBatchSizes() public {
        vm.startPrank(alice);
        // Warm-up: the very first anchor also initialises batchCount (0 -> 1), which costs
        // more than later increments. Measure two steady-state calls instead.
        anchor.anchorBatch(keccak256("warmup"), "aegis", 1);
        uint256 g0 = gasleft();
        anchor.anchorBatch(keccak256("a"), "aegis", 1);
        uint256 small = g0 - gasleft();
        uint256 g1 = gasleft();
        anchor.anchorBatch(keccak256("b"), "aegis", 1_000_000);
        uint256 large = g1 - gasleft();
        vm.stopPrank();
        uint256 diff = small > large ? small - large : large - small;
        emit log_named_uint("gas (1 record)", small);
        emit log_named_uint("gas (1,000,000 records)", large);
        // Only calldata byte values differ (zero vs non-zero bytes), a few hundred gas at most.
        assertLt(diff, 1_000);
    }

    // ---- fuzz --------------------------------------------------------------
    function testFuzz_anyRootAndCountStoredExactly(bytes32 root, uint64 count, string memory label) public {
        vm.assume(root != bytes32(0));
        vm.assume(count != 0);
        vm.assume(bytes(label).length <= 64);
        vm.prank(alice);
        uint256 id = anchor.anchorBatch(root, label, count);
        (bytes32 r, bytes32 lh,, uint64 c,,) = anchor.getBatch(id);
        assertEq(r, root);
        assertEq(c, count);
        assertEq(lh, sha256(bytes(label)));
    }

    function testFuzz_strangersNeverAnchor(address who, bytes32 root) public {
        vm.assume(who != alice);
        vm.prank(who);
        vm.expectRevert(AuditAnchor.NotAnchorer.selector);
        anchor.anchorBatch(root, "x", 1);
    }
}
