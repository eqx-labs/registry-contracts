// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {BLS} from "../lib/BLS.sol";

interface IBoltValidatorsV2 {
    struct ValidatorInfo {
        bytes20 pubkeyHash;
        uint32 maxCommittedGasLimit;
        address authorizedOperator;
        address controller;
    }

    /// @notice A registration of a BLS key
    struct Registration {
        /// BLS public key
        BLS.G1Point pubkey;
        /// BLS signature
        BLS.G2Point signature;
    }

    /// @notice An operator of BLS key[s]
    struct Operator {
        /// The address used to deregister from the registry and claim collateral
        address authorizedOperator;
        /// ETH collateral in GWEI
        uint56 collateralGwei;
        /// The block number when registration occurred
        uint32 registeredAt;
        /// The block number when deregistration occurred
        uint32 unregisteredAt;
    }

    error InvalidBLSSignature();
    error InvalidAuthorizedOperator();
    error UnsafeRegistrationNotAllowed();
    error UnauthorizedCaller();
    error InvalidPubkey();

    error InsufficientCollateral();
    error UnregistrationDelayTooShort();
    error OperatorAlreadyRegistered();
    error InvalidRegistrationRoot();
    error EthTransferFailed();
    error WrongOperator();
    error AlreadyUnregistered();
    error NotUnregistered();
    error UnregistrationDelayNotMet();
    error NoCollateralToClaim();
    error FraudProofWindowExpired();
    error FraudProofWindowNotMet();
    error DelegationSignatureInvalid();
    error SlashAmountExceedsCollateral();
    error NoCollateralSlashed();
    error NotRegisteredKey();
    error FraudProofMerklePathInvalid();
    error FraudProofChallengeInvalid();
    error CollateralOverflow();
    error DelegationExpired();
    error OperatorAlreadyUnregistered();

    function getAllValidators() external view returns (ValidatorInfo[] memory);

    function getValidatorByPubkey(
        BLS.G1Point calldata pubkey
    ) external view returns (ValidatorInfo memory);

    function getValidatorByPubkeyHash(
        bytes20 pubkeyHash
    ) external view returns (ValidatorInfo memory);

    function registerValidatorUnsafe(
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function registerValidator(
        Registration[] calldata regs,
        // BLS.G1Point calldata pubkey,
        // BLS.G2Point calldata signature,
        uint32 maxCommittedGasLimit,
        address authorizedOperator,
        bytes memory domainSeparator
    ) external returns(bytes32 registrationRoot);

    // function batchRegisterValidators(
    //     BLS.G1Point[] calldata pubkeys,
    //     BLS.G2Point calldata signature,
    //     uint32 maxCommittedGasLimit,
    //     address authorizedOperator
    // ) external;

    function batchRegisterValidatorsUnsafe(
        bytes20[] calldata pubkeyHashes,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) external;

    function updateMaxCommittedGasLimit(bytes20 pubkeyHash, uint32 maxCommittedGasLimit) external;

    function hashPubkey(
        BLS.G1Point calldata pubkey
    ) external view returns (bytes20);
}