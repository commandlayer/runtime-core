import { ethers } from "ethers";
import { verifyReceiptEd25519Sha256, CANONICAL_ID_SORTED_KEYS_V1 } from "./index.js";

function normalizePem(text: unknown): string | null {
  if (!text) return null;
  const pem = String(text).replace(/\\n/g, "\n").trim();
  return pem.includes("BEGIN") ? pem : null;
}

export async function verifyRuntimeReceiptV1WithEns(receipt: any, opts: {
  ethRpcUrl: string;
  signerEnsName: string;
  txtKey?: string; // default cl.receipt.pubkey.pem
  allowedCanonicals?: string[]; // default [CANONICAL_ID_SORTED_KEYS_V1]
}) {
  const { ethRpcUrl, signerEnsName } = opts;
  const txtKey = opts.txtKey || "cl.receipt.pubkey.pem";
  const allowedCanonicals = opts.allowedCanonicals || [CANONICAL_ID_SORTED_KEYS_V1];

  if (!ethRpcUrl) throw new Error("ethRpcUrl required");
  if (!signerEnsName) throw new Error("signerEnsName required");

  const provider = new ethers.JsonRpcProvider(ethRpcUrl);
  const resolver = await provider.getResolver(signerEnsName);
  if (!resolver) throw new Error("No resolver for signer ENS name");

  const txt = await resolver.getText(txtKey);
  const pem = normalizePem(txt);
  if (!pem) throw new Error(`Missing/invalid PEM in ENS TXT ${txtKey}`);

  return verifyReceiptEd25519Sha256(receipt, {
    publicKeyPemOrDer: pem,
    allowedCanonicals,
  });
}
