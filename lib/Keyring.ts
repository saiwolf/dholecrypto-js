"use strict";

const base64url = require('rfc4648').base64url;
import AsymmetricPublicKey from './key/AsymmetricPublicKey';
import AsymmetricSecretKey from './key/AsymmetricSecretKey';
import CryptoError from './error/CryptoError';
import Symmetric from './Symmetric';
import Util from './Util';
import { SodiumPlus } from 'sodium-plus';
import SymmetricKey from './key/SymmetricKey';
let sodium: SodiumPlus;


const KTYPE_ASYMMETRIC_SECRET = 'ed25519sk';
const KTYPE_ASYMMETRIC_PUBLIC = 'ed25519pk';
const KTYPE_SYMMETRIC         = 'symmetric';

export default class Keyring {
    keywrapKey: SymmetricKey | null;
    
    constructor(symKey: SymmetricKey) {
        if (symKey instanceof SymmetricKey) {
            this.keywrapKey = symKey;
        } else {
            this.keywrapKey = null;
        }
    }

    /**
     * @param {string} str
     * @returns {Buffer[]}
     */
    getComponents(str: string): Buffer[] {
        if (Buffer.isBuffer(str)) {
            str = str.toString('binary');
        }
        let header = Buffer.from(str.slice(0, 9), 'binary');
        let decoded = Util.stringToBuffer(base64url.parse(str.slice(9)));
        let checksum = decoded.slice(0, 16);
        let body = decoded.slice(16);
        return [header, body, checksum];
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {SymmetricKey|AsymmetricSecretKey|AsymmetricPublicKey}
     */
    async load(str: string | Buffer): Promise<SymmetricKey | AsymmetricSecretKey | AsymmetricPublicKey> {
        if (str.length < 9) {
            throw new CryptoError("String is too short to be a serialized key");
        }

        // Handle keywrap (but still decode unwrapped keys)
        if (Symmetric.isValidCiphertext(str)) {
            if (this.keywrapKey instanceof SymmetricKey) {
                str = await Symmetric.decrypt(str, this.keywrapKey as SymmetricKey);
            } else {
                throw new CryptoError("This key has been encrypted and you have not provided the keywrap key.");
            }
        }

        let header = str.slice(0, 9);
        if (Util.hashEquals(header, KTYPE_SYMMETRIC)) {
            return this.loadSymmetricKey(str);
        }
        if (Util.hashEquals(header, KTYPE_ASYMMETRIC_SECRET)) {
            return this.loadAsymmetricSecretKey(str);
        }
        if (Util.hashEquals(header, KTYPE_ASYMMETRIC_PUBLIC)) {
            return this.loadAsymmetricPublicKey(str);
        }
        throw new CryptoError("Invalid key header");
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {Promise<AsymmetricSecretKey>}
     */
    async loadAsymmetricSecretKey(str: any): Promise<AsymmetricSecretKey> {
        let header, body, checksum, calc;
        [header, body, checksum] = this.getComponents(str);
        calc = await sodium.crypto_generichash(
            Buffer.concat([header, body]),
            null,
            16
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 96) {
            throw new CryptoError("Invalid key length.");
        }
        let ret = new AsymmetricSecretKey(body.slice(0, 64));
        ret.injectBirationalEquivalent(body.slice(64,96));
        return ret;
    }


    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {AsymmetricPublicKey}
     */
    async loadAsymmetricPublicKey(str: any): Promise<AsymmetricPublicKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let header, body, checksum, calc;
        [header, body, checksum] = this.getComponents(str);
        calc = await sodium.crypto_generichash(
            Buffer.concat([header, body]),
            null,
            16
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 64) {
            throw new CryptoError("Invalid key length.");
        }
        let ret = new AsymmetricPublicKey(body.slice(0, 32));
        ret.injectBirationalEquivalent(body.slice(32, 64));
        return ret;
    }

    /**
     * Load a key from a string
     *
     * @param {string} str
     * @return {SymmetricKey}
     */
    async loadSymmetricKey(str: any): Promise<SymmetricKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let header, body, checksum, calc;
        [header, body, checksum] = this.getComponents(str);
        calc = await sodium.crypto_generichash(
            Buffer.concat([header, body]),
            null,
            16
        );
        if (!Util.hashEquals(calc, checksum)) {
            throw new CryptoError("Checksum failed. Corrupt key?");
        }
        if (body.length < 32) {
            throw new CryptoError("Invalid key length.");
        }
        return new SymmetricKey(body);
    }

    /**
     * Encrypts a string with the keywrap key. If it's not defined,
     * this function falls back to plaintext.
     *
     * @param {string} str
     * @returns {string}
     */
    keywrap(str: string): string {
        if (this.keywrapKey instanceof SymmetricKey) {
            Symmetric.encrypt(str, this.keywrapKey).then(value => {
                return value;
            });
        }
        return str;
    }

    /**
     * Serialize a key for storage
     *
     * @param {SymmetricKey|AsymmetricSecretKey|AsymmetricPublicKey} key
     * @return string
     */
    async save(key: SymmetricKey|AsymmetricSecretKey|AsymmetricPublicKey) {
        if (key instanceof AsymmetricSecretKey) {
            return this.keywrap(
                await this.saveAsymmetricSecretKey(key)
            );
        }
        if (key instanceof AsymmetricPublicKey) {
            return this.keywrap(
                await this.saveAsymmetricPublicKey(key)
            );
        }
        if (key instanceof SymmetricKey) {
            return this.keywrap(
                await this.saveSymmetricKey(key)
            );
        }
        throw new CryptoError("Invalid key type");
    }

    /**
     * @param {AsymmetricSecretKey} key
     * @return {string}
     */
    async saveAsymmetricPublicKey(key: AsymmetricPublicKey): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(key instanceof AsymmetricPublicKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_ASYMMETRIC_PUBLIC, 'binary');
        let birational = await key.getBirationalPublic();
        let checksum = await sodium.crypto_generichash(
            Buffer.concat([header, key.getBuffer(), birational.getBuffer()]),
            null,
            16
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer(), birational.getBuffer()])
        );
    }

    /**
     * @param {AsymmetricSecretKey} key
     * @return {string}
     */
    async saveAsymmetricSecretKey(key: AsymmetricSecretKey): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(key instanceof AsymmetricSecretKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_ASYMMETRIC_SECRET, 'binary');
        let birational = await key.getBirationalSecret();
        let checksum = await sodium.crypto_generichash(
            Buffer.concat([header, key.getBuffer(), birational.getBuffer()]),
            null,
            16
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer(), birational.getBuffer()])
        );
    }

    /**
     * @param {SymmetricKey} key
     * @return {string}
     */
    async saveSymmetricKey(key: SymmetricKey): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(key instanceof SymmetricKey)) {
            throw new TypeError();
        }
        let header = Buffer.from(KTYPE_SYMMETRIC, 'binary');
        let checksum = await sodium.crypto_generichash(
            Buffer.concat([header, key.getBuffer()]),
            null,
            16
        );
        return header + base64url.stringify(
            Buffer.concat([checksum, key.getBuffer()])
        );
    }
};
