"use strict";

import { base64url } from 'rfc4648';
import stringToBuffer from './Util';
import CryptoError from './error/CryptoError';
import { SodiumPlus, CryptographyKey } from 'sodium-plus';
import SymmetricKey from './key/SymmetricKey';
import Util from './Util';

const HEADER = "dhole100";
const ALLOWED_HEADERS = ["dhole100"];
const DOMAIN_SEPARATION = Buffer.from("DHOLEcrypto-Domain5eparatorConstant");

let sodium: SodiumPlus;

/**
 * @name Symmetric
 * @package dholecrypto
 */
export default class Symmetric
{
    /**
     * @param {string|Buffer} message
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static async auth(message: string | Buffer, symKey: SymmetricKey): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        message = Util.stringToBuffer(message);
        let subkey = await sodium.crypto_generichash(
            symKey.getBuffer(),
            new CryptographyKey(DOMAIN_SEPARATION)
        );
        let output = await sodium.crypto_auth(
            message,
            new CryptographyKey(subkey)
        );
        return output.toString('hex');
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static async encrypt(plaintext: string | Buffer, symKey: SymmetricKey): Promise<string> {
        return Symmetric.encryptWithAd(plaintext, symKey, "");
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} symKey
     * @returns {string}
     */
    static async decrypt(ciphertext: string | Buffer, symKey: SymmetricKey): Promise<string> {
        return Symmetric.decryptWithAd(ciphertext, symKey, "");
    }

    /**
     *
     * @param {string|Buffer} plaintext
     * @param {SymmetricKey} symKey
     * @param {string|Buffer} aad
     * @returns {string}
     */
    static async encryptWithAd(plaintext: string | Buffer, symKey: SymmetricKey, aad: string | Buffer = ""): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(symKey instanceof SymmetricKey)) {
            throw new TypeError('Argument 2 must be a SymmetricKey');
        }
        plaintext = Util.stringToBuffer(plaintext);
        aad = Util.stringToBuffer(aad);
        let nonce = await sodium.randombytes_buf(24);
        let ad;
        if (aad.length >= 1) {
            ad = Buffer.concat([Buffer.from(HEADER), nonce, aad]);
        } else {
            ad = Buffer.concat([Buffer.from(HEADER), nonce]);
        }
        let ciphertext = await sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            nonce,
            symKey,
            ad
        );

        return HEADER + base64url.stringify(
            Buffer.from(
                nonce.toString('binary') + ciphertext.toString('binary'),
                'binary'
            )
        );
    }

    /**
     *
     * @param {string|Buffer} ciphertext
     * @param {SymmetricKey} symKey
     * @param {string|Buffer} aad
     * @returns {string}
     */
    static async decryptWithAd(ciphertext: string | Buffer, symKey: SymmetricKey, aad: string | Buffer = ""): Promise<string> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (!(symKey instanceof SymmetricKey)) {
            throw new TypeError('Argument 2 must be a SymmetricKey');
        }
        ciphertext = Util.stringToBuffer(ciphertext);
        aad = Util.stringToBuffer(aad);
        if (ciphertext.length < 8) {
            throw new CryptoError("Ciphertext is too short");
        }
        let header = ciphertext.slice(0, 8).toString();
        if (!ALLOWED_HEADERS.includes(header)) {
            throw new CryptoError("Invalid header");
        }

        let decoded = Util.stringToBuffer(
            base64url.parse(ciphertext.slice(8).toString())
        );
        let nonce = decoded.slice(0, 24);
        let cipher = decoded.slice(24);

        let ad;
        if (aad.length >= 1) {
            ad = Buffer.concat([Buffer.from(HEADER), nonce, aad]);
        } else {
            ad = Buffer.concat([Buffer.from(HEADER), nonce]);
        }

        try {
            // SodiumPlus method `crypto_aead_xchacha20poly1305_ietf_decrypt` returns
            // a `Promise<Buffer>`, but the original code here declares a string as the
            // return type instead.
            //
            // So we explicity convert using toString().
            let result = await sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                cipher,
                nonce,
                symKey,
                ad
            );
            return result.toString();
        } catch (e) {
            /* istanbul ignore next */
            throw new CryptoError("Decryption failed");
        }
    }

    /**
     * @param {string|Buffer} message
     * @param {string|Buffer} mac
     * @param {SymmetricKey} symKey
     * @returns {boolean}
     */
    static async verify(message: string | Buffer, mac: string | Buffer, symKey: SymmetricKey): Promise<boolean> {
        if (!sodium) sodium = await SodiumPlus.auto();
        message = Util.stringToBuffer(message);        
        mac = Buffer.from(mac as string, 'hex');
        if (mac.length !== sodium.CRYPTO_AUTH_BYTES) {
            throw new CryptoError("MAC is not sufficient in length");
        }
        let subkey = await sodium.crypto_generichash(
            symKey.getBuffer(),
            new CryptographyKey(DOMAIN_SEPARATION)
        );
        return sodium.crypto_auth_verify(
            message,
            new CryptographyKey(subkey),
            mac
        );
    }

    /**
     * @param {string|Buffer} ciphertext
     * @returns {boolean}
     */
    static isValidCiphertext(ciphertext: string | Buffer): boolean {
        ciphertext = Util.stringToBuffer(ciphertext);
        if (ciphertext.length < 8) {
            return false;
        }
        let header = ciphertext.slice(0, 8).toString();
        return ALLOWED_HEADERS.includes(header);
    }
};
