// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title AuditAnchor
/// @notice Stores Merkle roots of audit-log / report batches so anyone can later prove a
///         record existed no later than a given block and was not altered since.
/// @dev Trust boundary: only addresses on the owner-managed allowlist may anchor. A batch
///      proves that THIS KEY anchored THIS ROOT at THIS TIME. It does not prove the key
///      belongs to a real Aegis/Gauntlet instance, nor that the underlying data is true.
///      Only the root is stored on-chain, so gas does not grow with batch size. The
///      source label is emitted in the event; its SHA-256 is stored for on-chain lookup.
contract AuditAnchor {
    struct Batch {
        bytes32 merkleRoot;
        bytes32 sourceLabelHash; // sha256(bytes(sourceLabel))
        address anchoredBy;
        uint64 recordCount;
        uint64 timestamp;
        uint64 blockNumber;
    }

    uint256 public constant MAX_LABEL_BYTES = 64;

    address public owner;
    uint256 public batchCount;
    mapping(address => bool) public isAnchorer;
    mapping(uint256 => Batch) private _batches;

    event BatchAnchored(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        string sourceLabel,
        uint64 recordCount,
        uint64 timestamp,
        address indexed anchoredBy
    );
    event AnchorerSet(address indexed account, bool allowed);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotAnchorer();
    error ZeroAddress();
    error ZeroRoot();
    error EmptyBatch();
    error LabelTooLong();
    error UnknownBatch();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Allow or disallow an address to anchor batches.
    function setAnchorer(address account, bool allowed) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        isAnchorer[account] = allowed;
        emit AnchorerSet(account, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Anchor a Merkle root. Duplicate roots are allowed: re-anchoring is harmless
    ///         and each call gets its own batchId (the earliest one is the earliest proof).
    function anchorBatch(bytes32 merkleRoot, string calldata sourceLabel, uint64 recordCount)
        external
        returns (uint256 batchId)
    {
        if (!isAnchorer[msg.sender]) revert NotAnchorer();
        if (merkleRoot == bytes32(0)) revert ZeroRoot();
        if (recordCount == 0) revert EmptyBatch();
        if (bytes(sourceLabel).length > MAX_LABEL_BYTES) revert LabelTooLong();

        batchId = ++batchCount;
        _batches[batchId] = Batch({
            merkleRoot: merkleRoot,
            sourceLabelHash: sha256(bytes(sourceLabel)),
            anchoredBy: msg.sender,
            recordCount: recordCount,
            timestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number)
        });
        emit BatchAnchored(batchId, merkleRoot, sourceLabel, recordCount, uint64(block.timestamp), msg.sender);
    }

    function getBatch(uint256 batchId)
        external
        view
        returns (
            bytes32 merkleRoot,
            bytes32 sourceLabelHash,
            address anchoredBy,
            uint64 recordCount,
            uint64 timestamp,
            uint64 blockNumber
        )
    {
        if (batchId == 0 || batchId > batchCount) revert UnknownBatch();
        Batch storage b = _batches[batchId];
        return (b.merkleRoot, b.sourceLabelHash, b.anchoredBy, b.recordCount, b.timestamp, b.blockNumber);
    }
}
