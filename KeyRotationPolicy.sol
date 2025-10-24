// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title KeyRotationPolicy
/// @notice Enforces time-delayed key rotation with emergency guardians.
/// @dev Use this to reduce exposure by rotating active signing keys on a schedule.
contract KeyRotationPolicy {
    address public currentKey; // active ECDSA key or key identifier
    address[] public guardians;
    uint256 public rotationDelay; // e.g., seconds
    uint256 public rotationProposedAt;
    address public proposedNewKey;
    bool public emergencyFrozen;

    event RotationProposed(address proposedKey, uint256 when);
    event RotationFinalized(address newKey);
    event EmergencyFreeze();
    event EmergencyUnfreeze();

    constructor(address _initialKey, address[] memory _guardians, uint256 _delay) {
        currentKey = _initialKey;
        guardians = _guardians;
        rotationDelay = _delay;
    }

    modifier onlyGuardian() {
        bool ok = false;
        for (uint256 i = 0; i < guardians.length; i++) {
            if (msg.sender == guardians[i]) { ok = true; break; }
        }
        require(ok, "not a guardian");
        _;
    }

    /// @notice Guardians or owner propose a rotation; finalize after delay.
    function proposeRotation(address newKey) external onlyGuardian {
        proposedNewKey = newKey;
        rotationProposedAt = block.timestamp;
        emit RotationProposed(newKey, rotationProposedAt);
    }

    function finalizeRotation() external onlyGuardian {
        require(proposedNewKey != address(0), "no proposal");
        require(block.timestamp >= rotationProposedAt + rotationDelay, "delay not passed");
        currentKey = proposedNewKey;
        proposedNewKey = address(0);
        rotationProposedAt = 0;
        emit RotationFinalized(currentKey);
    }

    function emergencyFreeze() external onlyGuardian {
        emergencyFrozen = true;
        emit EmergencyFreeze();
    }

    function emergencyUnfreeze() external onlyGuardian {
        emergencyFrozen = false;
        emit EmergencyUnfreeze();
    }

    // Example protected action
    function protectedAction(bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external {
        require(!emergencyFrozen, "frozen");
        bytes32 h = keccak256(abi.encodePacked(payload));
        address signer = ecrecover(prefixed(h), v, r, s);
        require(signer == currentKey, "not authorized");
        // perform action...
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
