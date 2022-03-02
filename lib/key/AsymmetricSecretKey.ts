"use strict";

import { SodiumPlus, Ed25519SecretKey, X25519SecretKey, CryptographyKey } from 'sodium-plus';
import AsymmetricPublicKey from './AsymmetricPublicKey';
import Util from '../Util';
let sodium: SodiumPlus;

/**
 * @class AsymmetricSecretKey
 * @package dholecrypto.key
 */
export default class AsymmetricSecretKey extends Ed25519SecretKey
{
    pk: AsymmetricPublicKey;
    buffer!: Buffer;
    birationalSecret!: X25519SecretKey;
    
    constructor(stringOrBuffer: string | Buffer, _apk?: AsymmetricPublicKey) {
        super(Util.stringToBuffer(stringOrBuffer));
        if (arguments.length > 1) {
            if (arguments[1] instanceof AsymmetricPublicKey) {
                this.pk = arguments[1];
            } else if (arguments[1] === null) {
                this.pk = new AsymmetricPublicKey(this.buffer.slice(32, 64));
            } else {
                throw new TypeError("Second argument must be an AsymmetricPublicKey");
            }
        } else {
            this.pk = new AsymmetricPublicKey(this.buffer.slice(32, 64));
        }
    }

    /**
     * @return {AsymmetricSecretKey}
     */
    static async generate(): Promise<AsymmetricSecretKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        let keypair: CryptographyKey = await sodium.crypto_sign_keypair();
        return new AsymmetricSecretKey(
            keypair.getBuffer().slice(0, 64),
            new AsymmetricPublicKey(keypair.getBuffer().slice(64, 96))
        );
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    async getBirationalSecret(): Promise<X25519SecretKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (typeof this.birationalSecret === 'undefined') {
            this.birationalSecret = await sodium.crypto_sign_ed25519_sk_to_curve25519(this);
        }
        return this.birationalSecret;
    }

    /**
     * @return {AsymmetricPublicKey}
     */
    getPublicKey(): AsymmetricPublicKey {
        return this.pk;
    }

    /**
     * @param {Buffer} buf
     * @returns {AsymmetricSecretKey}
     */
    injectBirationalEquivalent(buf: Buffer): AsymmetricSecretKey {
        this.birationalSecret = new X25519SecretKey(Util.stringToBuffer(buf));
        return this;
    }
};
