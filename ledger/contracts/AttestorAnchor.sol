// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AttestorAnchor
 * @notice Anchors Attestor ledger report hashes to a public blockchain.
 *         Each anchor stores BOTH the current report hash AND the previous
 *         report hash, making the chain linkage visible on-chain (in Etherscan
 *         event logs) — not just locally.
 */
contract AttestorAnchor {
    struct Anchor {
        bytes32 root;
        bytes32 previousRoot;
        uint256 timestamp;
        address submitter;
    }

    Anchor[] public anchors;

    /// @notice Emitted when a report is anchored. Both hashes visible in Etherscan logs.
    event ReportAnchored(
        bytes32 indexed root,
        bytes32 indexed previousRoot,
        uint256 timestamp,
        address indexed submitter
    );

    /// @notice Anchor a report hash with its chain predecessor.
    /// @param root The SHA-256 hash of the current report.
    /// @param previousRoot The SHA-256 hash of the previous report (0x00..00 if first).
    function anchorReport(bytes32 root, bytes32 previousRoot) external {
        anchors.push(Anchor({
            root: root,
            previousRoot: previousRoot,
            timestamp: block.timestamp,
            submitter: msg.sender
        }));
        emit ReportAnchored(root, previousRoot, block.timestamp, msg.sender);
    }

    /// @notice Get total anchored reports.
    function anchorCount() external view returns (uint256) {
        return anchors.length;
    }

    /// @notice Verify a root exists and get its chain predecessor.
    function verifyRoot(bytes32 root) external view returns (
        bool found, bytes32 previousRoot, uint256 timestamp, address submitter
    ) {
        for (uint256 i = anchors.length; i > 0; i--) {
            if (anchors[i-1].root == root) {
                Anchor memory a = anchors[i-1];
                return (true, a.previousRoot, a.timestamp, a.submitter);
            }
        }
        return (false, bytes32(0), 0, address(0));
    }
}
