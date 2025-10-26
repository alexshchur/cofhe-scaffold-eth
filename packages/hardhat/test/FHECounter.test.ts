/* eslint-disable @typescript-eslint/no-unused-vars */
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import hre from "hardhat";
import { cofhejs, Encryptable, FheTypes } from "cofhejs/node";

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

    /**
     * @dev Tests the basic increment functionality
     * Demonstrates:
     * - Reading encrypted values using hre.cofhe.mocks.expectPlaintext
     * - Logging FHE operations using hre.cofhe.mocks.withLogs
     */
    // it("Should increment the counter", async function () {
    //   const { counter, bob, alice } = await loadFixture(deployCounterFixture);
    //   const count = await counter.count();

    //   // `hre.cofhe.mocks.expectPlaintext` is used to verify that the encrypted value is 0
    //   // This uses the encrypted variable `count` and retrieves the plaintext value from the on-chain mock contracts
    //   // This kind of test can only be done in a mock environment where the plaintext value is known
    //   await hre.cofhe.mocks.expectPlaintext(count, 0n);

    //   // `hre.cofhe.mocks.withLogs` is used to log the FHE operations
    //   // This is useful for debugging and understanding the FHE operations
    //   // It will log the FHE operations to the console
    //   await hre.cofhe.mocks.withLogs("counter.increment()", async () => {
    //     await counter.connect(alice).increment();
    //   });

    //   const count2 = await counter.count();
    //   await hre.cofhe.mocks.expectPlaintext(count2, 1n);
    // });

    it("commit otp note (commitOtpNote) and then read it", async function () {
      const { counter, bob, alice } = await loadFixture(deployCounterFixture);
      // const count = await counter.count();
      // const { counter, bob } = await loadFixture(deployCounterFixture);

      const initializeResult = await hre.cofhe.initializeWithHardhatSigner(bob);
      await hre.cofhe.expectResultSuccess(initializeResult);

      // `cofhejs.encrypt` is used to encrypt the value
      // cofhejs must be initialized before `encrypt` can be called

      // TODO: try to pack what's needed into this value
      // otpNote contains: user-signed eth-address || user-email-hash of an email that was OTP-ed || timestamp
      // can I actually pack it into uint256?
      const user_address = "0x9a9b640f221fb8e7a283501367812c50c6805ed1";
      const timestamp = 123456789n;
      const email_with_salt_hash = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefan;

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

      const note_details = await counter.getOtpNote(note_key);

      // console.log("note_status:", note_status);
      console.log("note_committer:", note_details);

      const unsealed_user_address = await cofhejs.unseal(user_address_input.ctHash, FheTypes.Uint256);
      await hre.cofhe.expectResultValue(unsealed_user_address, BigInt(user_address));

      const unsealed_timestamp = await cofhejs.unseal(timestamp_input.ctHash, FheTypes.Uint64);
      await hre.cofhe.expectResultValue(unsealed_timestamp, timestamp);

      const unsealed_email_with_salt_hash = await cofhejs.unseal(emal_with_salt_input.ctHash, FheTypes.Uint256);
      await hre.cofhe.expectResultValue(unsealed_email_with_salt_hash, email_with_salt_hash);

      //   // `hre.cofhe.mocks.expectPlaintext` is used to verify that the encrypted value is 0
      //   // This uses the encrypted variable `count` and retrieves the plaintext value from the on-chain mock contracts
      //   // This kind of test can only be done in a mock environment where the plaintext value is known
      //   await hre.cofhe.mocks.expectPlaintext(count, 0n);

      //   // `hre.cofhe.mocks.withLogs` is used to log the FHE operations
      //   // This is useful for debugging and understanding the FHE operations
      //   // It will log the FHE operations to the console
      //   await hre.cofhe.mocks.withLogs("counter.increment()", async () => {
      //     await counter.connect(alice).increment();
      //     await counter.connect(alice).increment();
      //     await counter.connect(alice).increment();
      //   });

      //   const count2 = await counter.count();
      //   console.log("Encrypted count2:", count2);
      //   await hre.cofhe.mocks.expectPlaintext(count2, 3n);

      //   await hre.cofhe.mocks.withLogs("testing decrypting", async () => {
      //     await counter.connect(alice).decrypt();
      //     await new Promise(r => setTimeout(r, 10 * 1000)); // wait for 10 secs to match the mock decryptiong logic timing: _decryptResultReadyTimestamp[ctHash] = uint64(block.timestamp) + asyncOffset;
      //     const decrypted_result = await counter.getDecrypted();
      //     console.log("Decrypted result:", decrypted_result);
      //   });
    });
    // it("test decrypted", async function () {
    //   const { counter, bob, alice } = await loadFixture(deployCounterFixture);
    //   const count = await counter.count();

    //   // `hre.cofhe.mocks.expectPlaintext` is used to verify that the encrypted value is 0
    //   // This uses the encrypted variable `count` and retrieves the plaintext value from the on-chain mock contracts
    //   // This kind of test can only be done in a mock environment where the plaintext value is known
    //   await hre.cofhe.mocks.expectPlaintext(count, 0n);

    //   // `hre.cofhe.mocks.withLogs` is used to log the FHE operations
    //   // This is useful for debugging and understanding the FHE operations
    //   // It will log the FHE operations to the console
    //   await hre.cofhe.mocks.withLogs("counter.increment()", async () => {
    //     await counter.connect(alice).increment();
    //     await counter.connect(alice).increment();
    //     await counter.connect(alice).increment();
    //   });

    //   const count2 = await counter.count();
    //   console.log("Encrypted count2:", count2);
    //   await hre.cofhe.mocks.expectPlaintext(count2, 3n);

    //   await hre.cofhe.mocks.withLogs("testing decrypting", async () => {
    //     await counter.connect(alice).decrypt();
    //     await new Promise(r => setTimeout(r, 10 * 1000)); // wait for 10 secs to match the mock decryptiong logic timing: _decryptResultReadyTimestamp[ctHash] = uint64(block.timestamp) + asyncOffset;
    //     const decrypted_result = await counter.getDecrypted();
    //     console.log("Decrypted result:", decrypted_result);
    //   });
    // });

    /**
     * @dev Tests the cofhejs unseal functionality in mock environment
     * Demonstrates:
     * - Initializing FHE with a Hardhat signer
     * - Reading and unsealing encrypted values
     * - Verifying unsealed values match expectations
     */
    // it("cofhejs unseal (mocks)", async function () {
    //   await hre.cofhe.mocks.enableLogs("cofhejs unseal (mocks)");
    //   const { counter, bob } = await loadFixture(deployCounterFixture);

    //   // `hre.cofhe.initializeWithHardhatSigner` is used to initialize FHE with a Hardhat signer
    //   // Initialization is required before any `cofhejs.unseal` or `cofhejs.encrypt` operations can be performed
    //   // `initializeWithHardhatSigner` is a helper function that initializes FHE with a Hardhat signer
    //   // It returns a `Promise<Result<>>` type.

    //   // The `Result<T>` type looks like this:
    //   // {
    //   //   success: boolean,
    //   //   data: T (Permit | undefined in the case of initializeWithHardhatSigner),
    //   //   error: CofhejsError | null,
    //   // }
    //   const initializeResult = await hre.cofhe.initializeWithHardhatSigner(bob);

    //   // `hre.cofhe.expectResultSuccess` is used to verify that the `Result` is successful (success: true)
    //   // If the `Result` is not successful, the test will fail
    //   await hre.cofhe.expectResultSuccess(initializeResult);

    //   const count = await counter.count();

    //   // `cofhejs.unseal` is used to unseal the encrypted value
    //   // cofhejs must be initialized before `unseal` can be called
    //   const unsealedResult = await cofhejs.unseal(count, FheTypes.Uint32);

    //   // `hre.cofhe.expectResultValue` is used to verify that the `Result.data` is the expected value
    //   // If the `Result.data` is not the expected value, the test will fail
    //   await hre.cofhe.expectResultValue(unsealedResult, 0n);

    //   await counter.connect(bob).increment();

    //   const count2 = await counter.count();
    //   const unsealedResult2 = await cofhejs.unseal(count2, FheTypes.Uint32);
    //   await hre.cofhe.expectResultValue(unsealedResult2, 1n);

    //   await hre.cofhe.mocks.disableLogs();
    // });

    /**
     * @dev Tests the cofhejs encryption and value setting functionality
     * Demonstrates:
     * - Encrypting values using cofhejs
     * - Setting encrypted values in the contract
     * - Verifying encrypted values using both mocks and unsealing
    //  */
    // it("cofhejs encrypt (mocks)", async function () {
    //   const { counter, bob } = await loadFixture(deployCounterFixture);

    //   const initializeResult = await hre.cofhe.initializeWithHardhatSigner(bob);
    //   await hre.cofhe.expectResultSuccess(initializeResult);

    //   // `cofhejs.encrypt` is used to encrypt the value
    //   // cofhejs must be initialized before `encrypt` can be called
    //   const encryptResult = await cofhejs.encrypt([Encryptable.uint32(5n)] as const);

    //   const [encryptedInput] = await hre.cofhe.expectResultSuccess(encryptResult);
    //   await hre.cofhe.mocks.expectPlaintext(encryptedInput.ctHash, 5n);

    //   await counter.connect(bob).set(encryptedInput);

    //   const count = await counter.count();
    //   await hre.cofhe.mocks.expectPlaintext(count, 5n);

    //   const unsealedResult = await cofhejs.unseal(count, FheTypes.Uint32);
    //   await hre.cofhe.expectResultValue(unsealedResult, 5n);
    // });
  });
});
