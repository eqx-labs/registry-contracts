pragma solidity >=0.8.0 <0.9.0;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import {ValidatorData} from "./lib/ValidatorData.sol";
import {BLS12381} from "../lib/bls/BLS12381.sol";
import {BLSSignatureVerifier} from "../lib/bls/BLSSignatureVerifier.sol";
import {IBoltValidatorsV2} from "../interfaces/IBoltValidatorsV2.sol";
import {IBoltParametersV1} from "../interfaces/IBoltParametersV1.sol";

contract ValidatorsRegistry is OwnableUpgradeable, UUPSUpgradeable {
    // using BLS12381 for BLS12381.G1Point;
    // using ValidatorsLib for ValidatorData.ValidatorSet;
    using ValidatorsLibDataLib for ValidatorsDataLib.ValidatorSet;

    // ======= Storage ======

    event AddedValidatorPubkeyt(bytes32 indexed pubkeyHash);

    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init();

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