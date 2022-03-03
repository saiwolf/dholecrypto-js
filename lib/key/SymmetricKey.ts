import CryptoError from '../error/CryptoError';
import { SodiumPlus, CryptographyKey } from 'sodium-plus';
import Util from '../Util';
let sodium: SodiumPlus;

/**
 * @class SymmetricKey
 * @package dholecrypto.key
 */
export default class SymmetricKey extends CryptographyKey
{
    buffer!: Buffer;
    constructor(stringOrBuffer: string | Buffer) {
        super(Util.stringToBuffer(stringOrBuffer));
        if (this.buffer.length !== 32) {
            throw new CryptoError(
                `Symmetric keys must be 32 bytes. ${this.buffer.length} given.`
            );
        }
    }

    /**
     * @return {SymmetricKey}
     */
    static async generate(): Promise<SymmetricKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        return new SymmetricKey(
            await sodium.randombytes_buf(32)
        );
    }
};
