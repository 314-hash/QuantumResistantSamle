// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title OffChainAttestationBridge
/// @notice Offloads heavy post-quantum verification off-chain. Trusted attestors validate PQ signatures
///         and publish compact ECDSA-signed attestations on-chain which this contract verifies.
contract OffChainAttestationBridge {
    mapping(address => bool) public attestors; // authorized attestor ECDSA addresses
    address public admin;

    event AttestationAccepted(bytes32 attestationId, address indexed attestor);

    constructor(address[] memory initialAttestors) {
        admin = msg.sender;
        for (uint256 i = 0; i < initialAttestors.length; i++) {
            attestors[initialAttestors[i]] = true;
        }
    }

    /// @notice Submit an attestation signed by an authorized attestor (ECDSA).
    /// @param attestationId arbitrary ID / hash of the off-chain verification result
    /// @param v,r,s ECDSA signature over attestationId by attestor
    function submitAttestation(bytes32 attestationId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 pref = prefixed(attestationId);
        address signer = ecrecover(pref, v, r, s);
        require(attestors[signer], "unauthorized attestor");

        // process the attestation: e.g., credit funds, mark tx verified, etc.
        emit AttestationAccepted(attestationId, signer);
    }

    function setAttestor(address a, bool enabled) external {
        require(msg.sender == admin, "only admin");
        attestors[a] = enabled;
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    receive() external payable {}
}
