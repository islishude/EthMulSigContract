pragma solidity ^0.5.0;

contract MultiSig {
    uint256 public nonce;
    uint8 public threshold;

    address[] internal _members;
    mapping(address => bool) public membership;
    mapping(uint256 => mapping(address => bool)) confirmation;

    event Withdraw(
        address indexed from,
        address indexed to,
        uint256 indexed value
    );

    modifier OnlyMember {
        require(membership[msg.sender], "no permission to execute");
        _;
    }

    constructor(uint8 M, address[] memory __members) public payable {
        require(M > 0, "threshold must greater than zero");
        threshold = M;
        for (uint256 i = 0; i < __members.length; ++i) {
            if (membership[__members[i]] || __members[i] == address(0x0)) {
                continue;
            }
            membership[__members[i]] = true;
            _members.push(__members[i]);
        }
        require(
            threshold <= _members.length,
            "threshold must less than length of member"
        );
    }

    function() external payable {}

    function members() public view returns (address[] memory) {
        return _members;
    }

    function checkSig(
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
            "Invalid signs length"
        );
        require(v.length >= threshold, "Insufficient number of signatures");
        require(_to != address(this), "Can not transfer to current contract");
        for (uint256 i = 0; i < threshold; ++i) {
            bytes memory data = abi.encode(func, msg.sender, _token, _from, _to, _value, nonce);
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
    ) public OnlyMember returns (bool) {
        checkSig(0x4b239a29, v, r, s, address(0x0), address(this), _to, _value);
        _to.transfer(_value);
        emit Withdraw(msg.sender, _to, _value);
        return true;
    }

    // {
    //     "0xdd62ed3e": "allowance(address,address)",
    //     "0x095ea7b3": "approve(address,uint256)",
    //     "0x70a08231": "balanceOf(address)",
    //     "0x18160ddd": "totalSupply()",
    //     "0xa9059cbb": "transfer(address,uint256)",
    //     "0x23b872dd": "transferFrom(address,address,uint256)"
    // }    
    
    
    function isContract(address addr) internal view {
        assembly {
            if iszero(extcodesize(addr)) { revert(0, 0) }
        }
    }
    
    function handleReturnData() internal pure returns (bool result) {
        assembly {
            switch returndatasize()
            case 0 { // not a std erc20
                result := 1
            }
            case 32 { // std erc20
                returndatacopy(0, 0, 32)
                result := mload(0)
            }
            default { // anything else, should revert for safety
                revert(0, 0)
            }
        }
    }

    function erc20Transfer(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _to,
        uint256 _value
    ) public OnlyMember {
        isContract(_token);  
        checkSig(0xa9059cbb, v, r, s, _token, address(this), _to, _value);
        (bool success, ) = _token.call(abi.encodeWithSelector(0xa9059cbb, _to, _value));
        require(success);
        handleReturnData();
    }

    function erc20TransferFrom(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _from,
        address _to,
        uint256 _value
    ) public OnlyMember {
        isContract(_token);  
        checkSig(0x23b872dd, v, r, s, _token, _from, _to, _value);
        (bool success, ) = _token.call(abi.encodeWithSelector(0x23b872dd, _from, _to, _value));
        require(success);
        handleReturnData();
    }

    function erc20Approve(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _spender,
        uint256 _value
    ) public OnlyMember {
        isContract(_token);
        checkSig(0x095ea7b3, v, r, s, _token, address(this), _spender, _value);
        (bool success, ) = _token.call(abi.encodeWithSelector(0x994ead30, _spender, _value));
        require(success);
        handleReturnData();
    }
}
