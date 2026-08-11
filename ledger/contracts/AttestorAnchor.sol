// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AttestorAnchor
 * @notice Minimal contract for anchoring Attestor ledger root hashes
 *         to a public blockchain (Polygon Amoy testnet).
 *
 * Purpose: Make the local SHA-256 hash chain publicly, independently
 * verifiable. Anyone can query this contract to confirm that a specific
 * root hash was anchored at a specific time — no special access needed.
 *
 * Design: deliberately minimal. One function, one event, one mapping.
 * No admin, no upgradability, no access control beyond msg.sender tracking.
 */
contract AttestorAnchor {
    struct Anchor {
        bytes32 root;
        uint256 timestamp;
        address submitter;
    }

    /// @notice All anchored roots, newest last.
    Anchor[] public anchors;

    /// @notice Emitted when a new root is anchored.
    event RootAnchored(
        bytes32 indexed root,
        uint256 timestamp,
        address indexed submitter,
        uint256 index
    );

    /// @notice Anchor a ledger root hash on-chain.
    /// @param root The SHA-256 hash (as bytes32) of the latest chain state.
    function anchorRoot(bytes32 root) external {
        uint256 idx = anchors.length;
        anchors.push(Anchor({
            root: root,
            timestamp: block.timestamp,
            submitter: msg.sender
        }));
        emit RootAnchored(root, block.timestamp, msg.sender, idx);
    }

    /// @notice Get total number of anchored roots.
    function anchorCount() external view returns (uint256) {
        return anchors.length;
    }

    /// @notice Verify if a specific root has ever been anchored.
    /// @return found Whether the root exists, and its timestamp if so.
    function verifyRoot(bytes32 root) external view returns (bool found, uint256 timestamp, address submitter) {
        for (uint256 i = anchors.length; i > 0; i--) {
            if (anchors[i-1].root == root) {
                return (true, anchors[i-1].timestamp, anchors[i-1].submitter);
            }
        }
        return (false, 0, address(0));
    }
}
