# solcrypt

simple library for e2e encryption/decryption with solana type keys.

## quickstart

```ts
import {
    encryptMessage,
    decryptMessage,
    encodeText,
    decodeText,
} from "solcrypt";
import { Keypair } from "@solana/web3.js";

const aliceKeys = Keypair.generate();
const bobKeys = Keypair.generate();

const msg = encodeText("gm");

const encrypted = encryptMessage(msg, bobKeys.publicKey, aliceKeys);
const decrypted = decryptMessage(encrypted, aliceKeys.publicKey, bobKeys);

const decoded = decodeText(decrypted);

console.log(decoded);
```

See the [documentation](https://extrahash.github.io/solcrypt/) for further details.
