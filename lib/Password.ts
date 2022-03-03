const SymmetricKey = require('./key/SymmetricKey').default;
import Symmetric from './Symmetric';
import { SodiumPlus } from 'sodium-plus';
let sodium: SodiumPlus;

/**
 * Options for SodiumPlus Password Hashing API.
 * 
 * @property {string} alg - The algorithm to use.
 * @property {number} mem - Memory limit in bytes
 * @property {number} ops - Ops limit. Recommended default is 2.
 * 
 */
export type PasswordOptions = {
    alg: string;
    mem: number;
    ops: number;
}

const defaultOptions: PasswordOptions = {
    alg: 'argon2id',
    mem: 1 << 26, // 67108864 aka 64MiB
    ops: 2,
}

/**
 * @name Symmetric
 * @package dholecrypto
 */
export default class Password {
    symmetricKey: typeof SymmetricKey;
    options: PasswordOptions;
    /**
     * @param {SymmetricKey} symmetricKey
     * @param {object} options
     */
    constructor(symmetricKey: typeof SymmetricKey, options: PasswordOptions = defaultOptions) {
        if (!(symmetricKey instanceof SymmetricKey)) {
            throw new TypeError("Argument 1 must be an instance of SymmetricKey");
        }
        this.symmetricKey = symmetricKey;
        this.options = options;
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} ad
     * @return {string}
     */
    async hash(password: string | Buffer, ad: string | Buffer = ''): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let pwhash = await sodium.crypto_pwhash_str(
            password,
            this.options['ops'],
            this.options['mem']
        );
        if (ad.length > 0) {
            return Symmetric.encryptWithAd(pwhash, this.symmetricKey, ad);
        }
        return Symmetric.encrypt(pwhash, this.symmetricKey);
    }

    /**
     * @param {string|Buffer} pwhash
     * @param {string|Buffer} ad
     * @return {boolean}
     */
    async needsRehash(pwhash: string | Buffer, ad: string | Buffer = ''): Promise<boolean> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let decrypted;
        let encoded = `m=${this.options.mem >> 10},t=${this.options.ops},p=1`;
        if (ad.length > 0) {
            decrypted = await Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = await Symmetric.decrypt(pwhash, this.symmetricKey);
        }

        // $argon2id$v=19$m=65536,t=2,p=1$salt$hash
        //  \######/      \#############/
        //   \####/        \###########/
        //    `--'          `---------'
        //      \                /
        //     This is all we need
        let pieces = decrypted.split('$');
        let alg = pieces[1];
        let params = pieces[3];

        let result = await sodium.sodium_memcmp(
            Buffer.from(this.options.alg),
            Buffer.from(alg)
        );
        return result && await sodium.sodium_memcmp(
            Buffer.from(encoded),
            Buffer.from(params)
        );
    }

    /**
     * @param {string|Buffer} password
     * @param {string|Buffer} pwhash
     * @param {string|Buffer} ad
     * @return {boolean}
     */
    async verify(password: string | Buffer, pwhash: string | Buffer, ad: string | Buffer = ''): Promise<boolean> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let decrypted;
        if (ad.length > 0) {
            decrypted = await Symmetric.decryptWithAd(pwhash, this.symmetricKey, ad);
        } else {
            decrypted = await Symmetric.decrypt(pwhash, this.symmetricKey);
        }
        return sodium.crypto_pwhash_str_verify(
            password,
            decrypted.toString(),
        );
    }
};
