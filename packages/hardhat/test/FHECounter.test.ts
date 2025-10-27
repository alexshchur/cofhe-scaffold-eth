/* eslint-disable @typescript-eslint/no-unused-vars */
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import hre from "hardhat";
import { cofhejs, Encryptable, FheTypes } from "cofhejs/node";
import { OtpNoteStructOutput } from "../typechain-types/contracts/FHECounter";

/**
 * @file FHECounter.test.ts
 * @description Test suite for the FHECounter contract demonstrating FHE operations and testing utilities
 *
 * This test suite showcases the use of FHE testing tools and utilities:
 * - hre.cofhe: Internal FHE testing utilities
 * - cofhejs: FHE operations library
 * - Mock environment testing for FHE operations
 */

describe("Counter", function () {
  /**
   * @dev Deploys a fresh instance of the FHECounter contract for each test
   * Uses the third signer (bob) as the deployer
   */
  async function deployCounterFixture() {
    // Contracts are deployed using the first signer/account by default
    const [signer, signer2, bob, alice] = await hre.ethers.getSigners();

    const Counter = await hre.ethers.getContractFactory("FHECounter");
    const counter = await Counter.connect(bob).deploy();

    return { counter, signer, bob, alice };
  }

  describe("Functionality", function () {
    /**
     * @dev Setup and teardown for FHE testing
     * - Checks if we're in a MOCK environment (required for FHE testing)
     * - Provides options for enabling/disabling FHE operation logging
     */
    beforeEach(function () {
      if (!hre.cofhe.isPermittedEnvironment("MOCK")) this.skip();

      // NOTE: Uncomment for global logging
      // hre.cofhe.mocks.enableLogs()
    });

    afterEach(function () {
      if (!hre.cofhe.isPermittedEnvironment("MOCK")) return;

      // NOTE: Uncomment for global logging
      // hre.cofhe.mocks.disableLogs()
    });

    it("commit otp note (commitOtpNote), read it, then deposit and withdraw by authorized address", async function () {
      const { counter, bob, alice } = await loadFixture(deployCounterFixture);

      const user_address = "0x9a9b640f221fb8e7a283501367812c50c6805ed1";
      const timestamp = 123456789n;
      const email_with_salt_hash = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefan;

      const depositorInitializeResult = await hre.cofhe.initializeWithHardhatSigner(alice);
      await hre.cofhe.expectResultSuccess(depositorInitializeResult);

      const encrypted_by_depositor_email = await cofhejs.encrypt([Encryptable.uint256(email_with_salt_hash)] as const);

      const [depositor_email_input] = await hre.cofhe.expectResultSuccess(encrypted_by_depositor_email);
      await counter
        .connect(alice)
        .commitDepositNote(depositor_email_input, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" /* weth */, 1000n);

      // now read

      const depositNote = await counter.connect(alice).getDepositNote(depositor_email_input.ctHash);
      console.log({
        depositNote,
      });

      const initializeResult = await hre.cofhe.initializeWithHardhatSigner(bob);
      await hre.cofhe.expectResultSuccess(initializeResult);

      // `cofhejs.encrypt` is used to encrypt the value
      // cofhejs must be initialized before `encrypt` can be called

      const encrypted = await cofhejs.encrypt([
        Encryptable.address(user_address),
        Encryptable.uint64(timestamp),
        Encryptable.uint256(email_with_salt_hash),
      ] as const);

      console.log("encrypted:", encrypted);
      const [user_address_input, timestamp_input, emal_with_salt_input] =
        await hre.cofhe.expectResultSuccess(encrypted);

      await hre.cofhe.mocks.expectPlaintext(user_address_input.ctHash, BigInt(user_address));
      await hre.cofhe.mocks.expectPlaintext(timestamp_input.ctHash, timestamp);
      await hre.cofhe.mocks.expectPlaintext(emal_with_salt_input.ctHash, email_with_salt_hash);

      await counter.connect(bob).commitOtpNote(user_address_input, timestamp_input, emal_with_salt_input);

      const note_key = await counter.getOtpNoteKey(
        user_address_input.ctHash,
        timestamp_input.ctHash,
        emal_with_salt_input.ctHash,
      );

      console.log("note_key:", note_key);

      const note_details: OtpNoteStructOutput = await counter.getOtpNote(note_key);

      const [user_address_ct_handle, email_ct_handle, timestamp_ct_handle, otp_note_committer] = note_details;

      //       note details: {
      //   user_address_ct_handle: 114559657067922375818777741377286303958925648421173027698174777859324237383424n,
      //   email_ct_handle: 89820477399498921943140565757271670376756464862036245726427084342522139772928n,
      //   timestamp_ct_handle: 22396758350972728462713647775930637536329018080448761918573722901295838332160n,
      //   otp_note_committer: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC'
      // }
      // console.log("note details:", {
      //   user_address_ct_handle,
      //   email_ct_handle,
      //   timestamp_ct_handle,
      //   otp_note_committer,
      // });

      const unsealed_user_address = await cofhejs.unseal(user_address_ct_handle, FheTypes.Uint256);
      await hre.cofhe.expectResultValue(unsealed_user_address, BigInt(user_address));

      const unsealed_timestamp = await cofhejs.unseal(timestamp_ct_handle, FheTypes.Uint64);
      await hre.cofhe.expectResultValue(unsealed_timestamp, timestamp);

      const unsealed_email_with_salt_hash = await cofhejs.unseal(email_ct_handle, FheTypes.Uint256);
      await hre.cofhe.expectResultValue(unsealed_email_with_salt_hash, email_with_salt_hash);

      await counter.connect(alice).prepareWithdrawRequest(depositor_email_input.ctHash, note_key);

      const depositNoteAfterWithdrawRequest = await counter.connect(alice).getDepositNote(depositor_email_input.ctHash);

      console.log({
        depositNoteAfterWithdrawRequest,
      });

      await counter.connect(alice).decryptDepositNoteRecipient(depositor_email_input.ctHash);
      await new Promise(r => setTimeout(r, 11 * 1000)); // wait for 10 secs to match the mock decryptiong logic timing: _decryptResultReadyTimestamp[ctHash] = uint64(block.timestamp) + asyncOffset;

      const depositNoteAfterDecrypt = await counter.connect(alice).getDepositNote(depositor_email_input.ctHash);

      console.log({
        depositNoteAfterDecrypt,
      });

      await counter.connect(alice).withdraw(depositor_email_input.ctHash);
    });
  });
});
