/// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.17.0;

library Conversor {
    function bytesToBytes32(bytes calldata b, uint256 offset) external pure returns (bytes32) {
        bytes32 out;

        for (uint256 i = 0; i < 32; i++) {
            out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }

    function toHex16(bytes16 data) internal pure returns (bytes32 result) {
        result = (
            bytes32(data) & 0xFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000
        )
            | (
                (bytes32(data) & 0x0000000000000000FFFFFFFFFFFFFFFF00000000000000000000000000000000)
                    >> 64
            );
        result = (result & 0xFFFFFFFF000000000000000000000000FFFFFFFF000000000000000000000000)
            | ((result & 0x00000000FFFFFFFF000000000000000000000000FFFFFFFF0000000000000000) >> 32);
        result = (result & 0xFFFF000000000000FFFF000000000000FFFF000000000000FFFF000000000000)
            | ((result & 0x0000FFFF000000000000FFFF000000000000FFFF000000000000FFFF00000000) >> 16);
        result = (result & 0xFF000000FF000000FF000000FF000000FF000000FF000000FF000000FF000000)
            | ((result & 0x00FF000000FF000000FF000000FF000000FF000000FF000000FF000000FF0000) >> 8);
        result = (
            (result & 0xF000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000) >> 4
        ) | ((result & 0x0F000F000F000F000F000F000F000F000F000F000F000F000F000F000F000F00) >> 8);
        result = bytes32(
            0x3030303030303030303030303030303030303030303030303030303030303030 + uint256(result)
                + (
                    (
                        (
                            uint256(result)
                                + 0x0606060606060606060606060606060606060606060606060606060606060606
                        ) >> 4
                    ) & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
                ) * 7
        );
    }

    function toHex(bytes32 data) public pure returns (string memory) {
        return string(abi.encodePacked("0x", toHex16(bytes16(data)), toHex16(bytes16(data << 128))));
    }

    function bytesToString(bytes memory byteCode) public pure returns (string memory stringData) {
        uint256 blank = 0; //blank 32 byte value
        uint256 length = byteCode.length;

        uint256 cycles = byteCode.length / 0x20;
        uint256 requiredAlloc = length;

        if (
            length % 0x20 > 0 //optimise copying the final part of the bytes - to avoid looping with single byte writes
        ) {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank, so we don't smack the next stack entry
        }

        stringData = new string(requiredAlloc);

        //copy data in 32 byte blocks
        assembly {
            let cycle := 0

            for {
                let mc := add(stringData, 0x20) //pointer into bytes we're writing to
                let cc := add(byteCode, 0x20) //pointer to where we're reading from
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } { mstore(mc, mload(cc)) }
        }

        //finally blank final bytes and shrink size (part of the optimisation to avoid looping adding blank bytes1)
        if (length % 0x20 > 0) {
            uint256 offsetStart = 0x20 + length;
            assembly {
                let mc := add(stringData, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
                //now shrink the memory back so the returned object is the correct size
                mstore(stringData, length)
            }
        }
    }

    function iToHex(bytes memory buffer) public pure returns (string memory) {
        // Fixed buffer size for hexadecimal convertion
        bytes memory converted = new bytes(buffer.length * 2);

        bytes memory _base = "0123456789abcdef";

        for (uint256 i = 0; i < buffer.length; i++) {
            converted[i * 2] = _base[uint8(buffer[i]) / _base.length];
            converted[i * 2 + 1] = _base[uint8(buffer[i]) % _base.length];
        }

        return string(abi.encodePacked("0x", converted));
    }
}
