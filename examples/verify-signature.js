/**
 * Example usage of the Unisat signature verifier
 */

const { verifySignature } = require("../lib/verifier");

// Example data
const examples = [
  {
    name: "taproot Example",
    message: "hello",
    signature:
      "H/0APfJHqoNlsYitP357WXKCXIQmKPJI3OQQPtpabBUDPhxEBIMViDAACbSmrlfpvrl0Kwea5cDPeeL8PRXsujY=", // Replace with an actual signature
    address: "tb1pytamp3z7cskv4en02hx5xhugdmfrwjud0xxm8ekarvq5ghlpgpmsmandxy", // Replace with an actual address
  },
  {
    name: "Segwit Example",
    message: "hello",
    signature:
      "HxqvS5kVcNgwAKsrajjuQej4UOjTGLOGOe9zi5hDxZv1fvJO5FmxcVjw4xYXcKA5C1hYUpeJO+LrNo0KuJ4h4BE=", // Replace with an actual signature
    address: "tb1q2jwfvjzwfkpgty29fc4vd92x5zu37ek62ex6yu", // Replace with an actual address
  },
];

// Run the examples
console.log("=== Unisat Signature Verification Examples ===\n");

const runExamples = async () => {
  for (let index = 0; index < examples.length; index++) {
    const example = examples[index];
    console.log(`Example ${index + 1}: ${example.name}`);
    console.log(`Message: ${example.message}`);
    console.log(`Address: ${example.address}`);
    console.log(`Signature: ${example.signature.substring(0, 20)}...`);

    const isValid = await verifySignature(
      example.message,
      example.signature,
      example.address
    );

    console.log(`Result: ${isValid ? "✅ Valid" : "❌ Invalid"}`);
    console.log("-------------------------------------------\n");
  }
};

runExamples();

// How to use in your own code
console.log("How to use in your own code:");
console.log(`
const { verifySignature } = require('unisat-signature-verifier');

// Your data
const message = "Your message";
const signature = "Your base64 signature";
const address = "Your Bitcoin address (mainnet or testnet)";

// Verify the signature
const isValid = verifySignature(message, signature, address);
console.log(\`Signature is \${isValid ? 'valid' : 'invalid'}\`);
`);
