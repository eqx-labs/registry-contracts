// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/lib/ValidatorData.sol";

contract ValidatorDataTest is Test {
    using ValidatorData for ValidatorData.ValidatorSet;
    
    ValidatorData.ValidatorSet private validatorSet;
    bytes20 private constant SAMPLE_PUBKEY = bytes20(hex"1234567890123456789012345678901234567890");
    address private constant SAMPLE_CONTROLLER = address(0x1);
    address private constant SAMPLE_OPERATOR = address(0x2);

    function setUp() public {
        // Setup is called before each test
    }

    function testInsertValidator() public {
        // Get indexes for controller and operator
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        // Insert validator
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        
        // Verify validator exists
        assertTrue(validatorSet.contains(SAMPLE_PUBKEY));
        
        // Verify validator data
        ValidatorData._Validator memory validator = validatorSet.get(SAMPLE_PUBKEY);
        assertEq(validator.pubkeyHash, SAMPLE_PUBKEY);
        assertEq(validator.maxCommittedGasLimit, 1000000);
        assertEq(validator.controllerIndex, controllerIdx);
        assertEq(validator.authorizedOperatorIndex, operatorIdx);
    }

    function testCannotInsertDuplicateValidator() public {
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        
        // Try to insert the same validator again
        vm.expectRevert(abi.encodeWithSelector(ValidatorData.DuplicateValidator.selector, SAMPLE_PUBKEY));
        validatorSet.insert(SAMPLE_PUBKEY, 2000000, controllerIdx, operatorIdx);
    }

    function testUpdateMaxCommittedGasLimit() public {
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        validatorSet.updateMaxCommittedGasLimit(SAMPLE_PUBKEY, 2000000);
        
        ValidatorData._Validator memory validator = validatorSet.get(SAMPLE_PUBKEY);
        assertEq(validator.maxCommittedGasLimit, 2000000);
    }

    function testGetController() public {
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        
        address controller = validatorSet.getController(SAMPLE_PUBKEY);
        assertEq(controller, SAMPLE_CONTROLLER);
    }

    function testGetAuthorizedOperator() public {
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        
        address operator = validatorSet.getAuthorizedOperator(SAMPLE_PUBKEY);
        assertEq(operator, SAMPLE_OPERATOR);
    }

    function testGetAll() public {
        uint32 controllerIdx = ValidatorData.getOrInsert(validatorSet._controllers, SAMPLE_CONTROLLER);
        uint32 operatorIdx = ValidatorData.getOrInsert(validatorSet._authorizedOperators, SAMPLE_OPERATOR);
        
        validatorSet.insert(SAMPLE_PUBKEY, 1000000, controllerIdx, operatorIdx);
        
        ValidatorData._Validator[] memory validators = validatorSet.getAll();
        assertEq(validators.length, 1);
        assertEq(validators[0].pubkeyHash, SAMPLE_PUBKEY);
    }
}