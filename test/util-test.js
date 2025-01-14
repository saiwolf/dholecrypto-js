const assert = require('assert');
const expect = require('chai').expect;
const Util = require('../dist/lib/Util').default;
const hex = require('rfc4648').base16;

describe('Util', function () {
    it('hashEquals()', async function () {
        let a = await Util.randomBytes(32);
        let b = await Util.randomBytes(32);
        let c = await Util.randomBytes(31);
        expect(true).to.be.equal(await Util.hashEquals(a, a));
        expect(true).to.be.equal(await Util.hashEquals(b, b));
        expect(false).to.be.equal(await Util.hashEquals(a, b));
        expect(false).to.be.equal(await Util.hashEquals(b, a));
        expect(false).to.be.equal(await Util.hashEquals(a, c));
    });

    it('randomBytes() uniqueness', async function () {
        let a = await Util.randomBytes(16);
        let b = await Util.randomBytes(16);
        expect(a.toString('hex')).to.not.equals(b.toString('hex'));
    });

    it ('randomInt() uniqueness', async function () {
        let a, b;
        for (let i = 0; i < 1000; i++) {
            a = await Util.randomInt(0, Number.MAX_SAFE_INTEGER);
            b = await Util.randomInt(0, Number.MAX_SAFE_INTEGER);
            expect(a).to.not.equals(b);
        }
    });

    it ('randomInt() distribution', async function () {
        let space = [0,0,0,0,0];
        let iter = 0;
        let inc;
        let i;
        let failureSpotted;
        while (iter < 10000) {
            inc = await Util.randomInt(0, space.length - 1);
            space[inc]++;
            failureSpotted = false;
            for (i = 0; i < space.length; i++) {
                if (space[i] < 10) {
                    failureSpotted = true;
                    break;
                }
            }
            if (!failureSpotted) {
                break;
            }
            iter++;
        }
        expect(failureSpotted).to.be.equal(false);
        expect(iter).to.not.equals(10000);
        expect(await Util.randomInt(10, 4)).to.be.equal(10);
    });

    it('stringToBuffer()', async function () {
        let buf = await Util.stringToBuffer('abc');
        expect('616263').to.be.equal(buf.toString('hex'));
        buf = await Util.stringToBuffer(Buffer.from([0x41, 0x42, 0x43]));
        expect('414243').to.be.equal(buf.toString('hex'));
        buf = await Util.stringToBuffer(new Uint8Array([0x41, 0x42, 0x43]));
        expect('414243').to.be.equal(buf.toString('hex'));
        expect(() => {
            Util.stringToBuffer(12345)
        }).to.throw('Invalid type; string or buffer expected');
    });
});