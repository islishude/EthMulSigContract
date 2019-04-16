pragma solidity ^0.5.0;

contract ERC20Interface {
    function totalSupply() public view returns (uint);
    function balanceOf(address tokenOwner) public view returns (uint256 balance);
    function allowance(address tokenOwner, address spender)
        public
        view
        returns (uint256 remaining);
    function transfer(address to, uint256 tokens) public returns (bool success);
    function approve(address spender, uint256 tokens)
        public
        returns (bool success);
    function transferFrom(address from, address to, uint256 tokens)
        public
        returns (bool success);

    event Transfer(address indexed from, address indexed to, uint256 tokens);
    event Approval(
        address indexed tokenOwner,
        address indexed spender,
        uint256 tokens
    );
}

contract MultiSig {
    uint256 public nonce;
    uint8 public threshold;
    uint8 public sigv;

    address[] internal memberSet;
    mapping(address => bool) internal memberDict;

    event Withdraw(
        address indexed from,
        address indexed to,
        uint256 indexed value
    );

    modifier OnlyMember {
        require(memberDict[msg.sender], "no permission to execute");
        _;
    }

    constructor(uint8 M, address[] memory _members, uint8 chainid)
        public
        payable
    {
        require(M > 0, "threshold must greater than zero");
        threshold = M;
        for (uint256 i = 0; i < _members.length; ++i) {
            if (memberDict[_members[i]] || _members[i] == address(0x0)) {
                continue;
            }
            memberDict[_members[i]] = true;
            memberSet.push(_members[i]);
        }
        require(
            threshold <= memberSet.length,
            "threshold must less than length of member"
        );
        sigv = chainid * 2 + 36; // mainnet's chainid is 1
    }

    function() external payable {}


    function isMember(address _owner) public view returns (bool) {
        return memberDict[_owner];
    }

    function members() public view returns (address[] memory) {
        return memberSet;
    }

    function checkSig(
        bytes4 func,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _from,
        address _to,
        uint256 _value
    ) internal {
        require(
            r.length == s.length && r.length == threshold,
            "Invalid signs length"
        );
        address[] memory checked = new address[](threshold);
        for (uint256 i = 0; i < threshold; ++i) {
            bytes32 hash = keccak256(
                abi.encode(func, msg.sender, _token, _from, _to, _value, nonce)
            );
            address member = ecrecover(hash, sigv, r[i], s[i]);
            require(memberDict[member], "no permission to sign");
            for (uint256 j = 0; j < i; j++) {
                require(checked[j] != member, "duplicate signature");
            }
            checked[i] = member;
        }
        nonce++;
    }

    function transfer(
        bytes32[] memory r,
        bytes32[] memory s,
        address payable _to,
        uint256 _value
    ) public OnlyMember returns (bool) {
        checkSig(hex"4b239a29", r, s, address(0x0), address(this), _to, _value);
        _to.transfer(_value);
        emit Withdraw(msg.sender, _to, _value);
        return true;
    }

    function erc20Transfer(
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _to,
        uint256 _value
    ) public OnlyMember {
        checkSig(hex"0e9b380e", r, s, _token, address(this), _to, _value);
        // The wallet should check ERC20 Transfer event for transaction status
        ERC20Interface(_token).transfer(_to, _value);
    }

    function erc20TransferFrom(
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _from,
        address _to,
        uint256 _value
    ) public OnlyMember {
        checkSig(hex"91f099fe", r, s, _token, _from, _to, _value);
        ERC20Interface(_token).transferFrom(_from, _to, _value);
    }

    function erc20Approve(
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _spender,
        uint256 _value
    ) public OnlyMember {
        checkSig(hex"994ead30", r, s, _token, address(this), _spender, _value);
        ERC20Interface(_token).approve(_spender, _value);
    }
}
