/**
 * Main entry point for the Unisat signature verifier
 */

const { verifySignature } = require("./lib/verifier");
const readlineSync = require("readline-sync");

/**
 * Command-line interface for verifying signatures
 */
async function runCli() {
  console.log("=== Unisat Signature Verifier ===");
  console.log("Works with both mainnet and testnet addresses\n");

  const message = readlineSync.question("Enter the original message: ");
  const signature = readlineSync.question("Enter the signature (base64): ");
  const address = readlineSync.question("Enter the Bitcoin address: ");

  console.log("\nVerifying signature...");

  const isValid = await verifySignature(message, signature, address);

  console.log("\n=== Result ===");
  if (isValid) {
    console.log("✅ Signature is VALID");
  } else {
    console.log("❌ Signature is INVALID");
  }
}

// Run the CLI if this file is executed directly
if (require.main === module) {
  (async () => {
    await runCli();
  })();
}

// Export the verification function
module.exports = {
  verifySignature,
};
