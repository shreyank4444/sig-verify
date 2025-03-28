/**
 * Unisat Wallet Signature Verifier
 * Supports both mainnet and testnet addresses, including Taproot
 */

const bitcoin = require("bitcoinjs-lib");
const crypto = require("crypto");
const bs58check = require("bs58check");
const bech32 = require("bech32");
const secp256k1 = require("secp256k1");
const nobleSecp256k1 = require("noble-secp256k1");
const ecc = require("tiny-secp256k1");
const { ECPairFactory } = require("ecpair");

// Initialize bitcoin libraries
const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

// Helper function to convert public key to x-only format
const toXOnly = (pubkey) => {
  return pubkey.length === 33 ? pubkey.subarray(1, 33) : pubkey.subarray(0, 32);
};

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
 * Create a tagged hash (BIP340 style)
 * @param {string} tag - The tag for the hash
 * @param {Buffer} message - The message to hash
 * @returns {Buffer} - The tagged hash
 */
function taggedHash(tag, message) {
  const tagHash = crypto.createHash("sha256").update(Buffer.from(tag)).digest();
  const taggedMessage = Buffer.concat([tagHash, tagHash, message]);
  return crypto.createHash("sha256").update(taggedMessage).digest();
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
 * Verify a Schnorr signature using noble-secp256k1
 * @param {Buffer|Uint8Array} message - Message hash
 * @param {Buffer|Uint8Array} signature - 64-byte Schnorr signature
 * @param {Buffer|Uint8Array} publicKey - 32-byte x-only public key
 * @returns {Promise<boolean>} - Whether signature is valid
 */
async function verifySchnorrSignature(message, signature, publicKey) {
  try {
    // Ensure we're working with Uint8Arrays
    const messageArray =
      message instanceof Uint8Array ? message : new Uint8Array(message);
    const signatureArray =
      signature instanceof Uint8Array ? signature : new Uint8Array(signature);
    const publicKeyArray =
      publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey);

    // Log information for debugging
    console.log("Schnorr Verification Data:", {
      messageLength: messageArray.length,
      signatureLength: signatureArray.length,
      publicKeyLength: publicKeyArray.length,
    });

    // Verify the Schnorr signature using noble-secp256k1
    const isValid = await nobleSecp256k1.schnorr.verify(
      signatureArray,
      messageArray,
      publicKeyArray
    );

    return isValid;
  } catch (error) {
    console.error("Schnorr verification error:", error);
    return false;
  }
}

/**
 * Extract the internal key from a Taproot address
 * @param {string} address - Taproot address (bc1p... or tb1p...)
 * @returns {Buffer} - The 32-byte x-only internal key
 */
function extractTaprootInternalKey(address) {
  try {
    // First check if the address is potentially a Taproot address
    if (!address.startsWith("bc1p") && !address.startsWith("tb1p")) {
      throw new Error(`Not a Taproot address: ${address}`);
    }

    // For Taproot addresses, let's use bitcoinjs-lib's address handling instead
    // This provides better compatibility with different Taproot address formats
    const isTestnet = address.startsWith("tb1p");
    const network = isTestnet
      ? bitcoin.networks.testnet
      : bitcoin.networks.bitcoin;

    try {
      // Use bitcoinjs-lib to decode the address
      const output = bitcoin.address.fromBech32(address);

      if (output.version !== 1) {
        throw new Error(`Invalid Taproot version: ${output.version}`);
      }

      // The data should be the 32-byte x-only pubkey
      if (output.data.length !== 32) {
        throw new Error(`Invalid pubkey length: ${output.data.length}`);
      }

      console.log(
        `Successfully extracted internal key from address: ${address}`
      );
      return Buffer.from(output.data);
    } catch (bitcoinJsError) {
      console.error("BitcoinJS address parsing failed:", bitcoinJsError);

      // Fallback method for some Taproot addresses
      console.log("Trying fallback method for Taproot address parsing...");

      // Handle Bech32m addresses (newer Taproot format)
      try {
        // Try using bech32m decode
        const decoded = bech32.bech32m.decode(address);
        const data = bech32.bech32m.fromWords(decoded.words);

        // Extract the 32-byte key (skipping the version byte)
        if (data.length >= 33 && data[0] === 1) {
          console.log("Successfully extracted key using bech32m decode");
          return Buffer.from(data.slice(1));
        } else {
          throw new Error(
            `Invalid data format from bech32m decode: length=${data.length}`
          );
        }
      } catch (bech32mError) {
        console.error("Bech32m decode failed:", bech32mError);

        // Last resort - try to extract the key directly from the address
        // This is a simplified approach for demonstration
        console.log("Using last resort direct extraction method");

        // For Taproot addresses, the key is usually the last 32 bytes of program
        // This is not a standard way but might work for some addresses
        const addressParts = address.split("1");
        if (addressParts.length >= 2) {
          const program = addressParts[1];
          // Convert the program to binary and extract pubkey
          // This is a simplified approach and may not work for all addresses
          return Buffer.alloc(32, 0); // Placeholder for direct extraction
        }

        throw new Error("All Taproot address parsing methods failed");
      }
    }
  } catch (error) {
    console.error("Taproot address parsing error:", error);
    throw error;
  }
}

/**
 * Format a message for BIP340 Schnorr signing
 * @param {string} message - The raw message
 * @returns {Buffer} - The formatted message hash
 */
function formatTaprootMessage(message) {
  // Different wallets might use different message formats
  // We'll try three common approaches:

  // 1. Standard BIP340 tagged hash
  const tag = "BIP0340/challenge";
  const taggedMessage = Buffer.concat([
    Buffer.from("BTC Signed Message: ", "utf8"),
    Buffer.from(message, "utf8"),
  ]);
  const messageHash1 = taggedHash(tag, taggedMessage);

  // 2. Standard Bitcoin message hash (like legacy)
  const messageHash2 = magicHash(message);

  // 3. Raw SHA256 of message
  const messageHash3 = crypto
    .createHash("sha256")
    .update(Buffer.from(message))
    .digest();

  return { messageHash1, messageHash2, messageHash3 };
}

/**
 * Verify a Taproot signature (which actually uses ECDSA format in Unisat)
 * @param {string} message - Original message
 * @param {string} signatureBase64 - Signature in base64
 * @param {string} address - Taproot address (bc1p or tb1p)
 * @returns {Promise<boolean>} - Whether the signature is valid
 */
async function verifyTaprootSignature(message, signatureBase64, address) {
  try {
    console.log(
      "Verifying Taproot address signature with ECDSA method (Unisat format)"
    );

    // Decode the base64 signature
    const signatureBuffer = Buffer.from(signatureBase64, "base64");

    // Extract recovery ID from signature (first byte)
    if (signatureBuffer.length !== 65) {
      console.error(
        `Invalid signature length: ${signatureBuffer.length}, expected 65 bytes`
      );
      return false;
    }

    const recoveryFlag = signatureBuffer[0];
    const recoveryId = recoveryFlag - 27;
    const compressed = recoveryId >= 4;
    const actualRecoveryId = recoveryId - (compressed ? 4 : 0);

    console.log(
      `Signature header byte: ${recoveryFlag}, Recovery ID: ${actualRecoveryId}, Compressed: ${compressed}`
    );

    if (actualRecoveryId < 0 || actualRecoveryId > 3) {
      throw new Error(`Invalid recovery ID: ${actualRecoveryId}`);
    }

    // Extract the actual signature without the recovery ID
    const actualSignature = signatureBuffer.slice(1);

    // Create message hash
    const messageHash = magicHash(message);

    // Determine network
    const isTestnet = address.startsWith("tb1");
    const network = isTestnet
      ? bitcoin.networks.testnet
      : bitcoin.networks.bitcoin;

    try {
      // Recover public key using ECDSA recovery (just like regular Bitcoin addresses)
      const publicKey = recoverPublicKey(
        messageHash,
        actualSignature,
        actualRecoveryId
      );
      console.log(
        `Recovered public key (${publicKey.length} bytes) from signature`
      );

      // Convert to x-only public key for Taproot
      const xOnlyPubKey = toXOnly(publicKey);
      console.log(
        `Converted to x-only public key (${xOnlyPubKey.length} bytes)`
      );

      // Construct Taproot address from the recovered public key
      const taprootAddress = bitcoin.payments.p2tr({
        internalPubkey: xOnlyPubKey,
        network,
      }).address;

      console.log(`Reconstructed Taproot address: ${taprootAddress}`);
      console.log(`Original address: ${address}`);

      // Check if addresses match
      return taprootAddress === address;
    } catch (recoverError) {
      console.error(
        "Error recovering public key from signature:",
        recoverError
      );
      return false;
    }
  } catch (error) {
    console.error("Taproot ECDSA verification error:", error.message);
    return false;
  }
}

/**
 * Verify a Bitcoin signature with support for all address types
 * @param {string} message - The original message that was signed
 * @param {string} signature - The signature in base64 format
 * @param {string} address - The Bitcoin address (mainnet or testnet)
 * @returns {Promise<boolean>} - Whether the signature is valid
 */
async function verifySignature(message, signature, address) {
  try {
    // Handle Taproot addresses separately
    if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
      console.log(
        "Taproot address detected. Using Schnorr signature verification."
      );
      return await verifyTaprootSignature(message, signature, address);
    }

    // Regular ECDSA verification for non-Taproot addresses

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

/**
 * Generate a Taproot address from a public key
 * @param {string|Buffer} tweakedPublicKeyHex - The tweaked public key, either hex string or Buffer
 * @param {boolean} isTestnet - Whether to generate testnet address
 * @returns {string} - The Taproot address
 */
function generateTaprootAddress(tweakedPublicKeyHex, isTestnet = true) {
  const tweakedPubkey =
    typeof tweakedPublicKeyHex === "string"
      ? Buffer.from(tweakedPublicKeyHex, "hex")
      : tweakedPublicKeyHex;

  // Generate P2TR address
  const { address: taprootAddress } = bitcoin.payments.p2tr({
    internalPubkey: toXOnly(tweakedPubkey),
    network: isTestnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin,
  });

  return taprootAddress;
}

module.exports = {
  verifySignature,
  verifyTaprootSignature,
  verifySchnorrSignature,
  generateTaprootAddress,
  magicHash,
  taggedHash,
};
