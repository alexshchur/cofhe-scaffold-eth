// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

error OnlyTrustedOtpCommitterAllowed(address caller);

/**
 * @title FHECounter
 * @dev A simple counter contract that demonstrates the use of Fully Homomorphic Encryption (FHE)
 * to perform encrypted arithmetic operations. The counter value is stored in encrypted form,
 * allowing for private increments, decrements, and value updates.
 *
 * This contract showcases basic FHE operations:
 * - Encrypted state storage
 * - Encrypted arithmetic (addition and subtraction)
 * - Access control for encrypted values
 * - Value encryption and decryption
 */
import "hardhat/console.sol";

struct OtpNote {
    eaddress encUserAddress;
    euint256 encEmailWithSaltHash;
    euint64 encTimestampWithSaltHash;
    address pubCommitter;
}

struct DepositNote {
    euint256 encEmailWithSaltHash;
    address token;
    uint256 amount;
}

contract FHECounter {
    /// @notice The encrypted counter value
    address trusted_otp_committer = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    euint32 public count;

    /// @notice A constant encrypted value of 1 used for increments/decrements (gas saving)
    euint32 private ONE;

    mapping(uint256 => OtpNote) public otpNotes;

    mapping(euint256 depositEmailWithSaltHash => uint8) private depositNotes; // must be not boolean but state: deposited | requested | withdrawn
    mapping(euint256 depositEmailWithSaltHash => address) private depositNoteToken;
    mapping(euint256 depositEmailWithSaltHash => uint256) private depositNoteAmount;

    mapping(euint256 depositEmailWithSaltHash => eaddress) private depositNoteRecipientFromOtp; // when inited -> can withdraw

    mapping(uint256 paired_key => uint8) public withdraw_requests;

    /**
     * @dev Initializes the contract with encrypted values and sets up access permissions
     * - Sets ONE to encrypted value of 1
     * - Initializes count to encrypted value of 0
     * - Configures access permissions for the encrypted values
     */
    constructor() {
        ONE = FHE.asEuint32(1);
        count = FHE.asEuint32(0);

        // Allows anyone to read the initial encrypted value (0)
        // Also allows anyone to perform an operation USING the initial value
        FHE.allowGlobal(count);

        // Allows this contract to perform operations using the constant ONE
        FHE.allowThis(ONE);
    }

    modifier onlyTrustedOtpCommitter() {
        if (msg.sender != trusted_otp_committer) {
            revert OnlyTrustedOtpCommitterAllowed(msg.sender);
        }
        _;
    }

    // getter for ts explorability
    function getOtpNote(uint256 otpNoteKey) public view returns (OtpNote memory) {
        return otpNotes[otpNoteKey];
    }

    function getOtpNoteKey(
        eaddress user_address,
        euint64 timestamp_with_salt,
        euint256 email_with_salt_hash
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user_address, timestamp_with_salt, email_with_salt_hash));
    }

    function getDepositNote(
        euint256 depositEmailWithSaltHash
    ) public view returns (DepositNote memory, eaddress, bool, address) {
        DepositNote memory note;
        note.encEmailWithSaltHash = depositEmailWithSaltHash;
        note.token = depositNoteToken[depositEmailWithSaltHash];
        note.amount = depositNoteAmount[depositEmailWithSaltHash];

        eaddress recipient = depositNoteRecipientFromOtp[depositEmailWithSaltHash];

        (address recipient_plain, bool is_decrypted) = FHE.getDecryptResultSafe(
            depositNoteRecipientFromOtp[depositEmailWithSaltHash]
        );

        return (note, recipient, is_decrypted, recipient_plain);
    }

    function commitOtpNote(
        InEaddress memory _user_address,
        InEuint64 memory _timestamp_with_salt,
        InEuint256 memory _email_with_salt_hash
    ) public onlyTrustedOtpCommitter {
        eaddress user_address = FHE.asEaddress(_user_address);
        euint64 timestamp_with_salt = FHE.asEuint64(_timestamp_with_salt);
        euint256 email_with_salt_hash = FHE.asEuint256(_email_with_salt_hash);

        uint256 otpNoteKey = uint256(getOtpNoteKey(user_address, timestamp_with_salt, email_with_salt_hash));

        otpNotes[otpNoteKey].encEmailWithSaltHash = email_with_salt_hash;
        otpNotes[otpNoteKey].encUserAddress = user_address;
        otpNotes[otpNoteKey].encTimestampWithSaltHash = timestamp_with_salt;
        otpNotes[otpNoteKey].pubCommitter = msg.sender;

        FHE.allowThis(otpNotes[otpNoteKey].encEmailWithSaltHash); // now contract can write but not read it seems
        FHE.allowSender(otpNotes[otpNoteKey].encEmailWithSaltHash); //

        FHE.allowThis(otpNotes[otpNoteKey].encUserAddress); // now contract can write but not read it seems
        FHE.allowSender(otpNotes[otpNoteKey].encUserAddress); //

        FHE.allowThis(otpNotes[otpNoteKey].encTimestampWithSaltHash); // now contract can write but not read it seems
        FHE.allowSender(otpNotes[otpNoteKey].encTimestampWithSaltHash); //
    }

    function commitDepositNote(InEuint256 memory _depositEmailWithSaltHash, address token, uint256 amount) public {
        euint256 depositEmailWithSaltHash = FHE.asEuint256(_depositEmailWithSaltHash);
        // TODO: take token from user etc
        depositNotes[depositEmailWithSaltHash] = 1; // deposited
        depositNoteToken[depositEmailWithSaltHash] = token;
        depositNoteAmount[depositEmailWithSaltHash] = amount;

        FHE.allowThis(depositEmailWithSaltHash); // now contract can write but not read it seems
        FHE.allowSender(depositEmailWithSaltHash); //
    }

    function getPairedKey(euint256 depositNoteKey, uint256 otpNoteKey) public pure returns (uint256) {
        uint256 paired_key = uint256(keccak256(abi.encodePacked(depositNoteKey, otpNoteKey)));
        return paired_key;
    }

    function prepareWithdrawRequest(euint256 depositNote, uint256 otpNoteKey) public {
        if (depositNotes[depositNote] != 1) {
            revert("Deposit note unavailable for requesting withdrawal");
        }
        uint256 paired_key = getPairedKey(depositNote, otpNoteKey);
        if (withdraw_requests[paired_key] != 0) {
            revert("Withdraw request for this deposit+otp note already exists");
        }

        euint256 email_hash_from_deposit_note = depositNote;
        euint256 email_hash_from_otp_note = otpNotes[otpNoteKey].encEmailWithSaltHash;

        // TODO: I believe need this check?
        // if (uint256(email_hash_from_deposit_note) == uint256(email_hash_from_otp_note)) {
        //     revert("Deposit note and OTP note email hashes do not match");
        // }

        ebool hashes_match = FHE.eq(email_hash_from_deposit_note, email_hash_from_otp_note);

        withdraw_requests[paired_key] = 1; // requested

        depositNoteRecipientFromOtp[depositNote] = FHE.select(
            hashes_match,
            otpNotes[otpNoteKey].encUserAddress,
            FHE.asEaddress(0x0000000000000000000000000000000000000000)
        );

        FHE.allowThis(depositNoteRecipientFromOtp[depositNote]);
        FHE.allowSender(depositNoteRecipientFromOtp[depositNote]);
        depositNotes[depositNote] = 2; // request -prepared
    }

    function decryptDepositNoteRecipient(euint256 depositNote) public {
        if (depositNotes[depositNote] != 2) {
            revert("Deposit note not requested for withdrawal");
        }
        FHE.decrypt(depositNoteRecipientFromOtp[depositNote]);
        depositNotes[depositNote] = 3; // receipient decryption requested
    }

    function withdraw(euint256 depositNote) public {
        if (depositNotes[depositNote] != 3) {
            revert("Deposit note unavailable for withdraw");
        }

        (address recipient_plain, bool is_decrypted) = FHE.getDecryptResultSafe(
            depositNoteRecipientFromOtp[depositNote]
        );
        if (is_decrypted == false) {
            revert("Although requested, deposit note recipient not decrypted yet. Awaiting for decryption?");
        }

        address token = depositNoteToken[depositNote];
        uint256 amount = depositNoteAmount[depositNote];

        console.log("Withdrawing to:", recipient_plain, token, amount);

        depositNotes[depositNote] = 4; // withdrawn
    }

    function decrypt() public {
        FHE.decrypt(count);
    }

    function getDecrypted() public view returns (uint32, bool) {
        (uint32 value, bool is_decrypted) = FHE.getDecryptResultSafe(count);

        return (value, is_decrypted);
    }

    /**
     * @dev Increments the encrypted counter value by 1
     * Updates access permissions to allow the contract and sender to read the new value
     */
    function increment() public {
        // Performs an encrypted addition of count and ONE
        count = FHE.add(count, ONE);

        // Only this contract and the sender can read the new value
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    /**
     * @dev Decrements the encrypted counter value by 1
     * Updates access permissions to allow the contract and sender to read the new value
     */
    function decrement() public {
        count = FHE.sub(count, ONE);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    /**
     * @dev Sets the counter to a new encrypted value
     * @param value The new encrypted value to set the counter to
     * Updates access permissions to allow the contract and sender to read the new value
     */
    function set(InEuint32 memory value) public {
        count = FHE.asEuint32(value);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }
}
