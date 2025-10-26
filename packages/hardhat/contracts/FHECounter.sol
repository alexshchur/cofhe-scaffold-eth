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

contract FHECounter {
    /// @notice The encrypted counter value
    address trusted_otp_committer = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    euint32 public count;

    /// @notice A constant encrypted value of 1 used for increments/decrements (gas saving)
    euint32 private ONE;

    mapping(euint256 ctHash => bool) private otpNotes;
    mapping(euint256 ctHash => address) private otpNotesCommitter;

    mapping(euint256 ctHash => uint8) private depositNotes; // must be not boolean but state: deposited | requested | withdrawn
    mapping(euint256 ctHash => address) private depositNoteToken;
    mapping(euint256 ctHash => uint256) private depositNoteAmount;

    mapping(euint256 ctHash => eaddress) private depositNoteRecipientFromOtp; // when inited -> can withdraw

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
    function getOtpNoteStatus(euint256 ctHash) public view returns (bool) {
        return otpNotes[ctHash];
    }

    // getter for ts explorability
    function getOtpNoteCommitter(euint256 ctHash) public view returns (address) {
        return otpNotesCommitter[ctHash];
    }

    function commitOtpNote(InEuint256 memory _ctHash) public onlyTrustedOtpCommitter {
        // otpNote contains: user-signed eth-address || user-email-hash of an email that was OTP-ed || timestamp
        // AI: in what structure and how can I store this data? Need bitwise pack/unpack functions with FHE types
        euint256 ctHash = FHE.asEuint256(_ctHash);
        otpNotes[ctHash] = true;
        otpNotesCommitter[ctHash] = msg.sender;

        FHE.allowThis(ctHash); // now contract can write but not read it seems
        FHE.allowSender(ctHash); //
    }

    function commitDepositNote(euint256 depositNoteRef, address token, uint256 amount) public {
        // TODO: take token from user etc
        depositNotes[depositNoteRef] = 1; // deposited
        depositNoteToken[depositNoteRef] = token;
        depositNoteAmount[depositNoteRef] = amount;
    }

    function unpackEmailFromDepositNote(euint256 depositNote) public returns (euint256) {
        // TODO
        return FHE.asEuint256(123);
    }

    function unpackEmailFromOtpNote(euint256 otpNote) public returns (euint256) {
        // TODO
        return FHE.asEuint256(123);
    }

    function unpackRecipientFromOtpNote(euint256 otpNote) public returns (eaddress) {
        // TODO
        return FHE.asEaddress(0x1230DE36a047Abeb36Fe0E07F89305A73e74d22D); // random address
    }

    function prepareWithdrawRequest(euint256 depositNote, euint256 otpNote) public {
        if (depositNotes[depositNote] != 1) {
            revert("Deposit note unavailable for requesting withdrawal");
        }
        euint256 email_hash_from_deposit_note = unpackEmailFromDepositNote(depositNote);
        euint256 email_hash_from_otp_note = unpackEmailFromOtpNote(otpNote);

        ebool hashes_match = FHE.eq(email_hash_from_deposit_note, email_hash_from_otp_note);
        eaddress recipient = unpackRecipientFromOtpNote(otpNote);

        depositNoteRecipientFromOtp[depositNote] = recipient;
        depositNotes[depositNote] = 2; // request -prpared
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
