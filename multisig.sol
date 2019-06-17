pragma solidity ^0.5.0;

contract ERC20Interface {
    function totalSupply() public view returns (uint);
    function balanceOf(address tokenOwner)
        public
        view
        returns (uint256 balance);
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
            bytes memory data = abi.encode(
                func,
                msg.sender,
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
    ) public OnlyMember returns (bool) {
        checkSig(
            hex"4b239a29",
            v,
            r,
            s,
            address(0x0),
            address(this),
            _to,
            _value
        );
        _to.transfer(_value);
        emit Withdraw(msg.sender, _to, _value);
        return true;
    }

    function erc20Transfer(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _to,
        uint256 _value
    ) public OnlyMember {
        checkSig(hex"0e9b380e", v, r, s, _token, address(this), _to, _value);
        // The wallet should check ERC20 Transfer event for transaction status
        ERC20Interface(_token).transfer(_to, _value);
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
        checkSig(hex"91f099fe", v, r, s, _token, _from, _to, _value);
        ERC20Interface(_token).transferFrom(_from, _to, _value);
    }

    function erc20Approve(
        uint8[] memory v,
        bytes32[] memory r,
        bytes32[] memory s,
        address _token,
        address _spender,
        uint256 _value
    ) public OnlyMember {
        checkSig(
            hex"994ead30",
            v,
            r,
            s,
            _token,
            address(this),
            _spender,
            _value
        );
        ERC20Interface(_token).approve(_spender, _value);
    }
}
