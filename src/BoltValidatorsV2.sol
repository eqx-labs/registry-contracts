// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import { BLS } from "./lib/BLS.sol";
import { MerkleTree } from "./lib/MerkleTree.sol";
import { ISlasher } from "./interfaces/ISlasher.sol";
import { ValidatorsLib } from "./lib/ValidatorsLib.sol";
import { IBoltValidatorsV2 } from "./interfaces/IBoltValidatorsV2.sol";
import { IBoltParametersV1 } from "./interfaces/IBoltParametersV1.sol";

/// @title Bolt Validators
/// @notice This contract is responsible for registering validators and managing their configuration
/// @dev This contract is upgradeable using the UUPSProxy pattern. Storage layout remains fixed across upgrades
/// with the use of storage gaps.
/// See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
/// To validate the storage layout, use the Openzeppelin Foundry Upgrades toolkit.
/// You can also validate manually with forge: forge inspect <contract> storage-layout --pretty
contract BoltValidatorsV2 is IBoltValidatorsV2, OwnableUpgradeable, UUPSUpgradeable {
    // using BLS for BLS.G1Point;
    using BLS for *;
    using ValidatorsLib for ValidatorsLib.ValidatorSet;

    // ========= STORAGE =========

    /// @notice Bolt Parameters contract.
    IBoltParametersV1 public parameters;

    /// @notice Validators (aka Blockspace providers)
    /// @dev This struct occupies 6 storage slots.
    ValidatorsLib.ValidatorSet internal VALIDATORS;

    uint256 public ETH2_GENESIS_TIMESTAMP;

    /// @notice Mapping from registration merkle roots to Operator structs
    mapping(bytes32 registrationRoot => Operator) public registrations;

    // --> Storage layout marker: 7 slots

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     * This can be validated with the Openzeppelin Foundry Upgrades toolkit.
     *
     * Total storage slots: 50
     */
    uint256[43] private __gap;

    // ========= EVENTS =========

    /// @notice Emitted when a validator is registered
    /// @param pubkeyHash BLS public key hash of the validator
    event ValidatorRegistered(bytes32 indexed pubkeyHash);

    // ========= INITIALIZER =========

    /// @notice Initializer
    /// @param _owner Address of the owner of the contract
    /// @param _parameters Address of the Bolt Parameters contract
    function initialize(address _owner, address _parameters) public initializer {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function initializeV2(address _owner, address _parameters) public reinitializer(2) {
        __Ownable_init(_owner);

        parameters = IBoltParametersV1(_parameters);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // ========= VIEW FUNCTIONS =========

    /// @notice Get all validators in the system
    /// @dev This function should be used with caution as it can return a large amount of data.
    /// @return ValidatorInfo[] Array of validator info structs
    function getAllValidators() public view returns (ValidatorInfo[] memory) {
        ValidatorsLib._Validator[] memory _vals = VALIDATORS.getAll();
        ValidatorInfo[] memory vals = new ValidatorInfo[](_vals.length);
        for (uint256 i = 0; i < _vals.length; i++) {
            vals[i] = _getValidatorInfo(_vals[i]);
        }
        return vals;
    }

    /// @notice Get a validator by its BLS public key
    /// @param pubkey BLS public key of the validator
    /// @return ValidatorInfo struct
    function getValidatorByPubkey(
        BLS.G1Point calldata pubkey
    ) public view returns (ValidatorInfo memory) {
        return getValidatorByPubkeyHash(hashPubkey(pubkey));
    }

    /// @notice Get a validator by its BLS public key hash
    /// @param pubkeyHash BLS public key hash of the validator
    /// @return ValidatorInfo struct
    function getValidatorByPubkeyHash(
        bytes20 pubkeyHash
    ) public view returns (ValidatorInfo memory) {
        ValidatorsLib._Validator memory _val = VALIDATORS.get(pubkeyHash);
        return _getValidatorInfo(_val);
    }

    // ========= REGISTRATION LOGIC =========

    /// @notice Register a single Validator and authorize a Collateral Provider and Operator for it
    /// @dev This function allows anyone to register a single Validator. We do not perform any checks.
    /// @param pubkeyHash BLS public key hash for the Validator to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function registerValidatorUnsafe(
        bytes20 pubkeyHash,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _registerValidator(pubkeyHash, authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a single Validator and authorize an Operator for it.
    /// @dev This function allows anyone to register a single Validator. We perform an important check:
    /// The owner of the Validator (controller) must have signed the message with its BLS private key.
    ///
    /// Message format: `chainId || controller || sequenceNumber`
    /// @param regs it contains BLS public key and signature for the Validator to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    /// @param domainSeparator The domain seperator
    function registerValidator(
        Registration[] calldata regs,
        // BLS.G1Point calldata pubkey,
        // BLS.G2Point calldata signature,
        uint32 maxCommittedGasLimit,
        address authorizedOperator,
        bytes memory domainSeparator
    ) public returns (bytes32 registrationRoot) {
        registrationRoot = _merkleizeRegistrations(regs);

        if (registrationRoot == bytes32(0)) {
            revert InvalidRegistrationRoot();
        }

        if (registrations[registrationRoot].registeredAt != 0) {
            revert OperatorAlreadyRegistered();
        }

        registrations[registrationRoot] = Operator({
            authorizedOperator: authorizedOperator,
            collateralGwei: uint56(0),
            registeredAt: uint32(block.number),
            unregisteredAt: type(uint32).max
        });

        uint32 sequenceNumber = uint32(VALIDATORS.length() + 1);
        bytes memory message = abi.encodePacked(block.chainid, msg.sender, sequenceNumber);
        if (!BLS.verify(message, regs[0].signature, regs[0].pubkey, domainSeparator)) {
            revert InvalidBLSSignature();
        }

        _registerValidator(hashPubkey(regs[0].pubkey), authorizedOperator, maxCommittedGasLimit);
    }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeys List of BLS public keys for the Validators to be registered
    /// @param signature BLS aggregated signature of the registration message for this batch of Validators
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    // function batchRegisterValidators(
    //     BLS.G1Point[] calldata pubkeys,
    //     BLS.G2Point calldata signature,
    //     uint32 maxCommittedGasLimit,
    //     address authorizedOperator
    // ) public {
    //     uint32[] memory expectedValidatorSequenceNumbers = new uint32[](pubkeys.length);
    //     uint32 nextValidatorSequenceNumber = uint32(VALIDATORS.length() + 1);
    //     for (uint32 i = 0; i < pubkeys.length; i++) {
    //         expectedValidatorSequenceNumbers[i] = nextValidatorSequenceNumber + i;
    //     }

    //     // Reconstruct the unique message for which we expect an aggregated signature.
    //     // We need the msg.sender to prevent a front-running attack by an EOA that may
    //     // try to register the same validators
    //     bytes memory message = abi.encodePacked(block.chainid, msg.sender, expectedValidatorSequenceNumbers);

    //     // Aggregate the pubkeys into a single pubkey to verify the aggregated signature once
    //     BLS.G1Point memory aggPubkey = _aggregatePubkeys(pubkeys);

    //     if (!_verifySignature(message, signature, aggPubkey)) {
    //         revert InvalidBLSSignature();
    //     }

    //     bytes20[] memory pubkeyHashes = new bytes20[](pubkeys.length);
    //     for (uint256 i = 0; i < pubkeys.length; i++) {
    //         pubkeyHashes[i] = hashPubkey(pubkeys[i]);
    //     }

    //     _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    // }

    /// @notice Register a batch of Validators and authorize a Collateral Provider and Operator for them
    /// @dev This function allows anyone to register a list of Validators.
    /// @param pubkeyHashes List of BLS public key hashes for the Validators to be registered
    /// @param maxCommittedGasLimit The maximum gas that the Validator can commit for preconfirmations
    /// @param authorizedOperator The address of the authorized operator
    function batchRegisterValidatorsUnsafe(
        bytes20[] calldata pubkeyHashes,
        uint32 maxCommittedGasLimit,
        address authorizedOperator
    ) public {
        if (!parameters.ALLOW_UNSAFE_REGISTRATION()) {
            revert UnsafeRegistrationNotAllowed();
        }

        _batchRegisterValidators(pubkeyHashes, authorizedOperator, maxCommittedGasLimit);
    }

    // ========= UPDATE FUNCTIONS =========

    /// @notice Update the maximum gas limit that a validator can commit for preconfirmations
    /// @dev Only the `controller` of the validator can update this value.
    /// @param pubkeyHash The hash of the BLS public key of the validator
    /// @param maxCommittedGasLimit The new maximum gas limit
    function updateMaxCommittedGasLimit(bytes20 pubkeyHash, uint32 maxCommittedGasLimit) public {
        address controller = VALIDATORS.getController(pubkeyHash);
        if (msg.sender != controller) {
            revert UnauthorizedCaller();
        }

        VALIDATORS.updateMaxCommittedGasLimit(pubkeyHash, maxCommittedGasLimit);
    }

    // ========= HELPERS =========

    /// @notice Internal helper to register a single validator
    /// @param pubkeyHash BLS public key hash of the validator
    /// @param authorizedOperator Address of the authorized operator
    /// @param maxCommittedGasLimit Maximum gas limit that the validator can commit for preconfirmations
    function _registerValidator(bytes20 pubkeyHash, address authorizedOperator, uint32 maxCommittedGasLimit) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }
        if (pubkeyHash == bytes20(0)) {
            revert InvalidPubkey();
        }

        VALIDATORS.insert(
            pubkeyHash,
            maxCommittedGasLimit,
            VALIDATORS.getOrInsertController(msg.sender),
            VALIDATORS.getOrInsertAuthorizedOperator(authorizedOperator)
        );
        emit ValidatorRegistered(pubkeyHash);
    }

    /// @notice Internal helper to register a batch of validators
    /// @param pubkeyHashes List of BLS public key hashes of the validators
    /// @param authorizedOperator Address of the authorized operator
    /// @param maxCommittedGasLimit Maximum gas limit that the validators can commit for preconfirmations
    function _batchRegisterValidators(
        bytes20[] memory pubkeyHashes,
        address authorizedOperator,
        uint32 maxCommittedGasLimit
    ) internal {
        if (authorizedOperator == address(0)) {
            revert InvalidAuthorizedOperator();
        }

        uint32 authorizedOperatorIndex = VALIDATORS.getOrInsertAuthorizedOperator(authorizedOperator);
        uint32 controllerIndex = VALIDATORS.getOrInsertController(msg.sender);
        uint256 pubkeysLength = pubkeyHashes.length;

        for (uint32 i; i < pubkeysLength; i++) {
            bytes20 pubkeyHash = pubkeyHashes[i];

            if (pubkeyHash == bytes20(0)) {
                revert InvalidPubkey();
            }

            VALIDATORS.insert(pubkeyHash, maxCommittedGasLimit, controllerIndex, authorizedOperatorIndex);
            emit ValidatorRegistered(pubkeyHash);
        }
    }

    /// @notice Internal helper to get the ValidatorInfo struct from a _Validator struct
    /// @param _val Validator struct
    /// @return ValidatorInfo struct
    function _getValidatorInfo(
        ValidatorsLib._Validator memory _val
    ) internal view returns (ValidatorInfo memory) {
        return ValidatorInfo({
            pubkeyHash: _val.pubkeyHash,
            maxCommittedGasLimit: _val.maxCommittedGasLimit,
            authorizedOperator: VALIDATORS.getAuthorizedOperator(_val.pubkeyHash),
            controller: VALIDATORS.getController(_val.pubkeyHash)
        });
    }

    /// @notice Helper to compute the hash of a BLS public key
    /// @param pubkey Decompressed BLS public key
    /// @return Hash of the public key in compressed form
    function hashPubkey(
        BLS.G1Point memory pubkey
    ) public pure returns (bytes20) {
        uint256[2] memory compressedPubKey = pubkey.compress();
        bytes32 fullHash = keccak256(abi.encodePacked(compressedPubKey));
        // take the leftmost 20 bytes of the keccak256 hash
        return bytes20(uint160(uint256(fullHash)));
    }

    /// @notice Verify a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        external
        view
        returns (uint256 collateralGwei)
    {
        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);
    }

    /**
     *
     *                                Internal Functions                           *
     *
     */

    /// @notice Merkleizes an array of `Registration` structs
    /// @dev Leaves are created by abi-encoding the `Registration` structs, then hashing with keccak256.
    /// @param regs The array of `Registration` structs to merkleize
    /// @return registrationRoot The merkle root of the registration
    function _merkleizeRegistrations(Registration[] calldata regs) internal returns (bytes32 registrationRoot) {
        // Create leaves array with padding
        bytes32[] memory leaves = new bytes32[](regs.length);

        // Create leaf nodes by hashing Registration structs
        for (uint256 i = 0; i < regs.length; i++) {
            leaves[i] = keccak256(abi.encode(regs[i]));
            // emit KeyRegistered(i, regs[i], leaves[i]);
        }

        registrationRoot = MerkleTree.generateTree(leaves);
    }

    /// @notice Verifies a merkle proof against a given `registrationRoot`
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param leaf The leaf to verify
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyMerkleProof(bytes32 registrationRoot, bytes32 leaf, bytes32[] calldata proof, uint256 leafIndex)
        internal
        view
        returns (uint256 collateralGwei)
    {
        if (MerkleTree.verifyProofCalldata(registrationRoot, leaf, leafIndex, proof)) {
            collateralGwei = registrations[registrationRoot].collateralGwei;
        }
    }

    /// @notice Verifies a delegation was signed by a registered operator's key
    /// @dev The function will return the operator's collateral amount if the proof is valid or 0 if the proof is invalid.
    /// @dev The `signedDelegation.signature` is expected to be the abi-encoded `Delegation` message mixed with the Slasher's `DOMAIN_SEPARATOR`.
    /// @dev The function will revert if the delegation message expired, if the delegation signature is invalid, or if the delegation is not signed by the operator's BLS key.
    /// @param registrationRoot The merkle root generated and stored from the register() function
    /// @param registrationSignature The signature from the operator's previously registered `Registration`
    /// @param proof The merkle proof to verify the operator's key is in the registry
    /// @param leafIndex The index of the leaf in the merkle tree
    /// @param signedDelegation The SignedDelegation signed by the operator's BLS key
    /// @return collateralGwei The collateral amount in GWEI
    function _verifyDelegation(
        bytes32 registrationRoot,
        BLS.G2Point calldata registrationSignature,
        bytes32[] calldata proof,
        uint256 leafIndex,
        ISlasher.SignedDelegation calldata signedDelegation
    ) internal view returns (uint256 collateralGwei) {
        // Reconstruct leaf using pubkey in SignedDelegation to check equivalence
        bytes32 leaf = keccak256(abi.encode(signedDelegation.delegation.proposerPubKey, registrationSignature));

        collateralGwei = _verifyMerkleProof(registrationRoot, leaf, proof, leafIndex);

        if (collateralGwei == 0) {
            revert NotRegisteredKey();
        }

        // Reconstruct Delegation message
        bytes memory message = abi.encode(signedDelegation.delegation);

        // Check if the delegation is fresh
        if (signedDelegation.delegation.validUntil < _getSlotFromTimestamp(block.timestamp)) {
            revert DelegationExpired();
        }

        // Recover Slasher contract domain separator
        bytes memory domainSeparator = ISlasher(signedDelegation.delegation.slasher).DOMAIN_SEPARATOR();

        if (
            !BLS.verify(message, signedDelegation.signature, signedDelegation.delegation.proposerPubKey, domainSeparator)
        ) {
            revert DelegationSignatureInvalid();
        }
    }

    /// @notice Executes the slash function of the Slasher contract and returns the amount of GWEI to be slashed
    /// @dev The function will revert if the `slashAmountGwei` is 0, if the `slashAmountGwei` exceeds the operator's collateral, or if the Slasher.slash() function reverts.
    /// @param signedDelegation The SignedDelegation signed by the operator's BLS key
    /// @param evidence Arbitrary evidence to slash the operator, required by the Slasher contract
    /// @param collateralGwei The operator's collateral amount in GWEI
    /// @return slashAmountGwei The amount of GWEI to be slashed
    function _executeSlash(
        ISlasher.SignedDelegation calldata signedDelegation,
        bytes calldata evidence,
        uint256 collateralGwei
    ) internal returns (uint256 slashAmountGwei) {
        slashAmountGwei = ISlasher(signedDelegation.delegation.slasher).slash(signedDelegation.delegation, evidence);

        if (slashAmountGwei == 0) {
            revert NoCollateralSlashed();
        }

        if (slashAmountGwei > collateralGwei) {
            revert SlashAmountExceedsCollateral();
        }
    }

    /// @notice Get the slot number from a given timestamp. Assumes 12 second slot time.
    /// @param _timestamp The timestamp
    /// @return slot The slot number
    function _getSlotFromTimestamp(uint256 _timestamp) internal view returns (uint256 slot) {
        slot = (_timestamp - ETH2_GENESIS_TIMESTAMP) / 12;
    }
}