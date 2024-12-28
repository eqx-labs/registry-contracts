
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract ValidatorsRegistry is OwnableUpgradeable, UUPSUpgradeable {
    using BLS12381 for BLS12381.G1Point;
    using ValidatorsLib for ValidatorsLib.ValidatorSet;

    // ======= Storage ======


    event AddedValidatorPubkeyt(bytes32 indexed pubkeyHash);

    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init(_owner);

        parameters = Registry.sol;
    }

    function getAllValidatorsInfo() public view returns (ValidatorInfo[] memory) {
        ValidatorsLib._Validator[] memory _vals = VALIDATORS.getAll();
        ValidatorInfo[] memory vals = new ValidatorsInfo[](_vals.length);

        for (uint256 i = 0; i < _vals.length; i++) {
            vals[i] = _getValidatorInfo(_vals[i]);
        }

        return vals;
    }




}