// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title LamportOneTimeWallet
/// @notice Minimal Lamport one-time signature verifier using keccak256 as the hash.
/// @dev Lamport signatures are hash-based and considered post-quantum resistant.
///     This contract demonstrates verification only and expects the public key
///     to be committed once. One-time use must be enforced by user/application logic.
contract LamportOneTimeWallet {
    address public owner;

    // Lamport public key: pub[i][0] and pub[i][1] for each bit of message hash (256 bits)
    bytes32[256][2] public lamportPub;

    // Prevent reuse: once a message-hash is accepted, mark used
    mapping(bytes32 => bool) public usedMessageHash;

    event Executed(address indexed to, uint256 value, bytes data, bytes32 msgHash);

    constructor(bytes32[256][2] memory _lamportPub) {
        owner = msg.sender;
        lamportPub = _lamportPub;
    }

    /// @notice Verifies a Lamport signature over `to|value|data` and executes if valid.
    /// @param to destination
    /// @param value wei to send
    /// @param data calldata bytes
    /// @param signature array of 256 preimages (one per bit)
    function execute(
        address to,
        uint256 value,
        bytes calldata data,
        bytes32[256] calldata signature
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(to, value, data));
        require(!usedMessageHash[msgHash], "message already used (one-time)");
        require(verifyLamport(msgHash, signature), "invalid lamport signature");

        usedMessageHash[msgHash] = true;

        (bool ok, ) = to.call{value: value}(data);
        require(ok, "call failed");

        emit Executed(to, value, data, msgHash);
    }

    /// @dev verify lamport signature for keccak256(msg)
    function verifyLamport(bytes32 msgHash, bytes32[256] calldata signature) public view returns (bool) {
        bytes32 digest = msgHash;
        // iterate bits 0..255 of digest
        for (uint256 i = 0; i < 256; i++) {
            uint8 bit = uint8((uint256(digest) >> i) & 1);
            bytes32 h = keccak256(abi.encodePacked(signature[i]));
            if (bit == 0) {
                if (h != lamportPub[0][i]) return false;
            } else {
                if (h != lamportPub[1][i]) return false;
            }
        }
        return true;
    }

    // allow contract to receive ETH
    receive() external payable {}
}
