const assert = require('assert');
const expect = require('chai').expect;
const AsymmetricSecretKey = require('../dist/lib/key/AsymmetricSecretKey').default;
const AsymmetricPublicKey = require('../dist/lib/key/AsymmetricPublicKey').default;
const SymmetricKey = require('../dist/lib/key/SymmetricKey').default;

describe('Keys', function() {
    it('SymmetricKey', async function () {
        expect(() => {
            new SymmetricKey('x')
        }).to.throw('Symmetric keys must be 32 bytes. 1 given.');
    });
    it('AsymmetricSecretKey', async function () {
        expect(() => {
            new AsymmetricSecretKey('x')
        }).to.throw('Ed25519 secret keys must be 64 bytes long');
        expect(() => {
            new AsymmetricSecretKey(Buffer.alloc(64), 'x')
        }).to.throw('Second argument must be an AsymmetricPublicKey');
        new AsymmetricSecretKey(Buffer.alloc(64), null);
    });
    it('AsymmetricPublicKey', async function () {
        expect(() => {
            new AsymmetricPublicKey('x')
        }).to.throw('Ed25519 public keys must be 32 bytes long');
    });
});
