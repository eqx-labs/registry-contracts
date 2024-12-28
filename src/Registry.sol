// ToDo: add the parameters here || RENAME TO REGISTRY
// Also add manager logic here

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import { BLS } from "./lib/BLS.sol";
import { MerkleTree } from "./lib/MerkleTree.sol";
import { IRegistry } from "./IRegistry.sol";
import { ISlasher } from "./ISlasher.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";


contract Registry is IRegistry, OwnableUpgradeable, UUPSUpgradeable {

    // ====== CONTRACT PARAMS ============

    uint48 public CHALLENGE_TIMEOUT_WINDOW;

    uint256 public COST_OF_CHALLENGE;

    uint256 public SLOT_TIME;

    uint256[47] private __gap;

    function initializeParams(
        address a,
        uint48 _challengeTimeoutWindow,
        uint48 _costOfChallenge,
        uint48 _slotTime
    ) public initializer {
        __Ownable_init();

        CHALLENGE_TIMEOUT_WINDOW = _challengeTimeoutWindow;
        COST_OF_CHALLENGE = _costOfChallenge;
        SLOT_TIME = _slotTime;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    function setChallengeTimeoutWindow(
        uint48 challengeTimeoutWindow
    ) public onlyOwner {
        CHALLENGE_TIMEOUT_WINDOW = challengeTimeoutWindow;
    }

    function setCostOfChallenge(
        uint48 costOfChallenge
    ) public onlyOwner {
        COST_OF_CHALLENGE = costOfChallenge;
    }

    function setSlotTime(
        uint48 slotTime
    ) public onlyOwner {
        SLOT_TIME = slotTime;
    }

    /// ====== END CONTRACT PARAMS ==========

    /// ====== Validator Register Functions =====
    
    /// ====== END VALIDATOR REGISTER FUNCTIONS ====
}
