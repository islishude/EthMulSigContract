// SPDX-License-Identifier: MIT

pragma solidity ^0.7.0;

contract MultiSig {
    uint256 public nonce;
    uint8 public threshold;

    mapping(address => bool) public membership;
    mapping(uint256 => mapping(address => bool)) confirmation;

    modifier OnlyMember {
        require(membership[msg.sender], "no permission to execute");
        _;
    }

    modifier OnlyContract(address addr) {
        assembly {
            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }
        _;
    }

    constructor(uint8 M, address[] memory members) payable {
        require(M > 0, "threshold must greater than zero");
        require(
            threshold <= members.length,
            "threshold must less than length of member"
        );
        threshold = M;
        for (uint256 i = 0; i < members.length; ++i) {
            require(members[i] != address(0x0), "empty address");
            require(!membership[members[i]], "duplicate address");
            membership[members[i]] = true;
        }
    }

    receive() external payable {}

    function verify(
        bytes4 func,
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _from,
        address _to,
        uint256 _value
    ) internal {
        require(
            v.length == r.length && r.length == s.length,
            "Invalid signatures length"
        );
        require(v.length >= threshold, "Insufficient number of signatures");
        require(_to != address(this), "Can not transfer to current contract");
        for (uint256 i = 0; i < threshold; ++i) {
            bytes memory data = abi.encode(
                func,
                _token,
                _from,
                _to,
                _value,
                nonce
            );
            bytes32 hash = keccak256(data);
            address member = ecrecover(hash, v[i], r[i], s[i]);
            require(membership[member], "no permission to sign");
            require(!confirmation[nonce][member], "duplicate signature");
        }
        nonce++;
    }

    function transfer(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address payable _to,
        uint256 _value
    ) external OnlyMember {
        verify(0x207c76fa, v, r, s, address(0x0), address(this), _to, _value);
        (bool success, ) = _to.call{value: _value}(new bytes(0));
        require(success, "ETHER_TRANSFER_FAILED");
    }

    function ERC20Transfer(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _to,
        uint256 _value
    ) external OnlyMember OnlyContract(_token) {
        verify(0xb9367bc2, v, r, s, _token, address(this), _to, _value);
        (bool success, bytes memory data) = _token.call(
            abi.encodeWithSelector(0xa9059cbb, _to, _value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "ERC20_TRANSFER_FAILED"
        );
    }

    function ERC20TransferFrom(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _from,
        address _to,
        uint256 _value
    ) external OnlyMember OnlyContract(_token) {
        verify(0xc14e130d, v, r, s, _token, _from, _to, _value);
        (bool success, bytes memory data) = _token.call(
            abi.encodeWithSelector(0x23b872dd, _from, _to, _value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "ERC20_TRANSFER_FROM_FAILED"
        );
    }

    function ERC20Approve(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _spender,
        uint256 _value
    ) external OnlyMember OnlyContract(_token) {
        verify(0x3a4fd5f3, v, r, s, _token, address(this), _spender, _value);
        (bool success, bytes memory data) = _token.call(
            abi.encodeWithSelector(0x994ead30, _spender, _value)
        );
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            "ERC20_APPROVE_FAILED"
        );
    }
}
