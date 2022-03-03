import { SodiumPlus, Ed25519PublicKey, X25519PublicKey } from 'sodium-plus';
import Util from '../Util';
let sodium: SodiumPlus;

/**
 * @class AsymmetricPublicKey
 * @package dholecrypto.key
 */
export default class AsymmetricPublicKey extends Ed25519PublicKey
{
    birationalPublic!: X25519PublicKey;
    constructor(stringOrBuffer: string | Buffer) {
        super(Util.stringToBuffer(stringOrBuffer));
    }

    /**
     * Get a birationally equivalent X25519 secret key
     * for use in crypto_box_*
     *
     * @return {Buffer} length = 32
     */
    async getBirationalPublic(): Promise<X25519PublicKey> {
        if (!sodium) sodium = await SodiumPlus.auto();
        if (typeof this.birationalPublic === 'undefined') {
            this.birationalPublic = await sodium.crypto_sign_ed25519_pk_to_curve25519(this);
        }
        return this.birationalPublic;
    }

    injectBirationalEquivalent(buf: Buffer) {
        this.birationalPublic = new X25519PublicKey(Util.stringToBuffer(buf));
        return this;
    }
};
