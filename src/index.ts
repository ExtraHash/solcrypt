import { Keypair, PublicKey } from "@solana/web3.js";
import { EDX2 } from "./EDX2";
import { box, randomBytes, sign } from "tweetnacl";
import { Sha256 } from "@aws-crypto/sha256-browser";

/**
 * An encrypted message, which includes both the encrypted data and the nonce it was encrypted with.
 */
export interface EncryptedMessage {
    nonce: Uint8Array;
    message: Uint8Array;
}

/**
 * A helper function to encode text as an Uint8Array.
 *
 * @param s The text to encode to bytes.
 * @returns The text encoded as a Uint8Array.
 */
export function encodeText(s: string): Uint8Array {
    return new TextEncoder().encode(s);
}

/**
 * A helper function to decode Uint8Array bytes back into text.
 *
 * @param b The bytes to decode to text.
 * @returns The decoded text as a string.
 */
export function decodeText(b: Uint8Array): string {
    return new TextDecoder().decode(b);
}

/**
 * Encrypts a message to send to a recipient.
 *
 * @param msg The message to encrypt, as a Uint8Array.
 * @param receiverPubKey The recipient's Solana PublicKey.
 * @param senderKeypair The sender's Solana keypair.
 * @returns The encrypted message.
 */
export function encryptMessage(
    msg: Uint8Array,
    receiverPubKey: PublicKey,
    senderKeypair: Keypair
): EncryptedMessage {
    const senderEDX2 = new EDX2(senderKeypair);
    const recipientX2Pubkey = EDX2.convertPubKey(receiverPubKey);
    const nonce = makeNonce();

    return {
        nonce,
        message: box(
            msg,
            nonce,
            recipientX2Pubkey,
            senderEDX2.x2Keys.secretKey
        ),
    };
}

/**
 * Decrypts a message received from a sender.
 *
 * @param message The encrypted message and nonce.
 * @param senderPubKey The sender's Solana PublicKey.
 * @param receiverKeypair The receiver's Solana Keypair.
 * @returns The decrypted message.
 */
export function decryptMessage(
    message: EncryptedMessage,
    senderPubKey: PublicKey,
    receiverKeypair: Keypair
): Uint8Array {
    const senderPublicKeyX2 = EDX2.convertPubKey(senderPubKey);
    const receiverEDX2 = new EDX2(receiverKeypair);

    const opened = box.open(
        message.message,
        message.nonce,
        senderPublicKeyX2,
        receiverEDX2.x2Keys.secretKey
    );

    if (opened === null) {
        throw new Error("Decrypt failed");
    }

    return opened;
}

/**
 * Generates a derived keypair from a signature of an inacessible Master Key with only the
 * sign() function exposed. Care must be taken to inform the user not to create a duplicate signature
 * elsewhere or the derived key (not the master key) could be compromised
 *
 * See: https://crypto.stackexchange.com/questions/67291/generating-a-key-pair-using-a-signature-generated-by-an-existing-key
 *
 * @param signature
 * @returns The derived keypair
 */
export async function deriveKey(signature: Uint8Array) {
    const hash = new Sha256();
    hash.update(signature);
    return Keypair.fromSeed(await hash.digest());
}

/**
 * Creates a nonce to encrypt a message.
 *
 * @returns a 24 byte nonce.
 */
function makeNonce(): Uint8Array {
    return randomBytes(24);
}
