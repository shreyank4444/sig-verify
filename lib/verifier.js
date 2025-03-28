/**
 * Unisat Wallet Signature Verifier
 * Supports both mainnet and testnet Bitcoin addresses
 */

const bitcoin = require("bitcoinjs-lib");
const crypto = require("crypto");
const bs58check = require("bs58check");
const bech32 = require("bech32");
const secp256k1 = require("secp256k1");

/**
 * Create a Bitcoin message magic prefix
 * @param {string} message - The message to prefix
 * @param {string} networkPrefix - The network-specific prefix (default: Bitcoin message prefix)
 * @returns {Buffer} - The prefixed message hash as a Buffer
 */
function magicHash(message, networkPrefix = "Bitcoin Signed Message:\n") {
  const messageBuffer = Buffer.from(message);
  const prefixBuffer = Buffer.from(networkPrefix);

  const varintPrefix = Buffer.from([prefixBuffer.length]);
  const varintMessage = Buffer.alloc(9);
  let offset = 0;

  if (messageBuffer.length < 253) {
    varintMessage[0] = messageBuffer.length;
    offset = 1;
  } else if (messageBuffer.length < 65536) {
    varintMessage[0] = 253;
    varintMessage.writeUInt16LE(messageBuffer.length, 1);
    offset = 3;
  } else if (messageBuffer.length < 4294967296) {
    varintMessage[0] = 254;
    varintMessage.writeUInt32LE(messageBuffer.length, 1);
    offset = 5;
  } else {
    varintMessage[0] = 255;
    varintMessage.writeUInt32LE(messageBuffer.length & 0xffffffff, 1);
    varintMessage.writeUInt32LE(
      Math.floor(messageBuffer.length / 0x100000000),
      5
    );
    offset = 9;
  }

  const combined = Buffer.concat([
    varintPrefix,
    prefixBuffer,
    varintMessage.slice(0, offset),
    messageBuffer,
  ]);

  return crypto
    .createHash("sha256")
    .update(crypto.createHash("sha256").update(combined).digest())
    .digest();
}

/**
 * Recover a public key from a signature and message hash
 * @param {Buffer} messageHash - The message hash
 * @param {Buffer} signature - The signature (without recovery ID)
 * @param {number} recoveryId - The recovery ID (0-3)
 * @returns {Buffer} - The recovered public key
 */
function recoverPublicKey(messageHash, signature, recoveryId) {
  try {
    // Make sure signature is in the right format for secp256k1 (64 bytes: r + s)
    if (signature.length !== 64) {
      throw new Error(`Invalid signature length: ${signature.length}`);
    }

    // Use secp256k1 to recover the public key
    const publicKey = secp256k1.ecdsaRecover(
      signature,
      recoveryId,
      messageHash,
      true
    );
    return Buffer.from(publicKey);
  } catch (error) {
    console.error("Public key recovery error:", error.message);
    throw error;
  }
}

/**
 * Verify a Bitcoin signature with support for both mainnet and testnet addresses
 * @param {string} message - The original message that was signed
 * @param {string} signature - The signature in base64 format
 * @param {string} address - The Bitcoin address (mainnet or testnet)
 * @returns {boolean} - Whether the signature is valid
 */
function verifySignature(message, signature, address) {
  try {
    // Decode the signature
    const signatureBuffer = Buffer.from(signature, "base64");

    // Extract recovery ID from signature (first byte) and remove it
    const recoveryFlag = signatureBuffer[0];
    const recoveryId = recoveryFlag - 27;
    const compressed = recoveryId >= 4;
    const actualRecoveryId = recoveryId - (compressed ? 4 : 0);

    if (actualRecoveryId < 0 || actualRecoveryId > 3) {
      throw new Error(`Invalid recovery ID: ${actualRecoveryId}`);
    }

    // Extract the actual signature without the recovery ID
    const actualSignature = signatureBuffer.slice(1);

    // Create message hash
    const messageHash = magicHash(message);

    // Determine network from address
    const isTestnet =
      address.startsWith("m") ||
      address.startsWith("n") ||
      address.startsWith("2") ||
      address.startsWith("tb1");

    const network = isTestnet
      ? bitcoin.networks.testnet
      : bitcoin.networks.bitcoin;

    // Special case for Taproot addresses
    if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
      console.log(
        "Taproot address detected. Taproot signature verification is not fully supported yet."
      );
      return false; // Taproot needs special handling
    }

    try {
      // Recover public key directly using secp256k1
      const publicKey = recoverPublicKey(
        messageHash,
        actualSignature,
        actualRecoveryId
      );

      // Determine address type and verify
      let computedAddress;

      if (
        address.startsWith("1") ||
        address.startsWith("m") ||
        address.startsWith("n")
      ) {
        // Legacy address (P2PKH)
        computedAddress = bitcoin.payments.p2pkh({
          pubkey: publicKey,
          network,
        }).address;
      } else if (address.startsWith("3") || address.startsWith("2")) {
        // P2SH address
        const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: publicKey, network });
        computedAddress = bitcoin.payments.p2sh({
          redeem: p2wpkh,
          network,
        }).address;
      } else if (address.startsWith("bc1q") || address.startsWith("tb1q")) {
        // Bech32 address (P2WPKH)
        computedAddress = bitcoin.payments.p2wpkh({
          pubkey: publicKey,
          network,
        }).address;
      } else {
        throw new Error(`Unsupported address format: ${address}`);
      }

      return computedAddress === address;
    } catch (recoverError) {
      console.error("Error recovering public key:", recoverError);
      throw new Error("Public key recovery failed");
    }
  } catch (error) {
    console.error("Verification error:", error.message);
    return false;
  }
}

module.exports = {
  verifySignature,
  magicHash,
};
