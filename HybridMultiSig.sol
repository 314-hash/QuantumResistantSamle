// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title HybridMultiSig
/// @notice Hybrid approach: require owner ECDSA approval + reveal of a preimage bound to a stored hash (PQ commitment).
/// @dev This is an architectural mitigation: the heavy PQ verification happens off-chain; contract
///     requires a second factor (a revealed preimage or one-time proof) that is hard to forge.
contract HybridMultiSig {
    address public owner;
    bytes32 public pqCommitment; // commit to a post-quantum public key or verification token

    event Executed(address to, uint256 value, bytes data);

    constructor(bytes32 _pqCommitment) {
        owner = msg.sender;
        pqCommitment = _pqCommitment;
    }

    /// @notice Execute transaction if signed by owner (ECDSA) and caller reveals pqPreimage whose hash equals pqCommitment.
    /// @param to destination
    /// @param value wei
    /// @param data calldata payload
    /// @param v,r,s ECDSA signature components over txHash signed by owner
    /// @param pqPreimage preimage that must hash to pqCommitment (e.g., serialized PQ public key)
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes calldata pqPreimage
    ) external {
        bytes32 txHash = keccak256(abi.encodePacked(address(this), to, value, data));
        // recover signer
        address signer = ecrecover(prefixed(txHash), v, r, s);
        require(signer == owner, "invalid ECDSA signature");

        // verify PQ commitment reveal
        require(keccak256(pqPreimage) == pqCommitment, "invalid PQ preimage");

        (bool ok, ) = to.call{value: value}(data);
        require(ok, "call failed");

        emit Executed(to, value, data);
    }

    // helper to mimic Ethereum Signed Message prefixing
    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // allow owner to update pqCommitment (e.g., rotate to a new PQ pubkey commitment)
    function updatePQCommitment(bytes32 newCommitment) external {
        require(msg.sender == owner, "only owner");
        pqCommitment = newCommitment;
    }

    receive() external payable {}
}
