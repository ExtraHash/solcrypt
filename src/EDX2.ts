import ed2curve from "ed2curve";
import { Keypair, PublicKey } from "@solana/web3.js";

/**
 * A class that takes a Solana type ed25519 signing keypair as a parameter and converts it to its respective
 * X25519 encryption keypair, allowing access to both.
 */
export class EDX2 {
    /**
     * Converts an ed25519 public key to its respective X25519 public key.
     *
     * @param pubkey The public key to convert to X25519
     * @returns
     */
    public static convertPubKey(pubkey: PublicKey): Uint8Array {
        const convert = ed2curve.convertPublicKey(pubkey.toBuffer());
        if (convert === null) {
            throw new Error("Pubkey convert failed");
        }
        return convert;
    }

    /**
     * The ed25519 keypair
     */
    public edKeys: Keypair;

    /**
     * The X25519 keypair
     */
    public x2Keys: {
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    };

    /**
     *
     * @param ed2Keypair The Solana keypair to convert.
     */
    constructor(ed2Keypair: Keypair) {
        this.edKeys = ed2Keypair;

        this.x2Keys = {
            publicKey: ed2curve.convertPublicKey(
                ed2Keypair.publicKey.toBuffer()
            )!,
            secretKey: ed2curve.convertSecretKey(ed2Keypair.secretKey),
        };

        if (!this.x2Keys.publicKey) {
            throw new Error("Public key convert failed.");
        }
    }
}
