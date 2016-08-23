/// <reference path="../typings/globals/mocha/index.d.ts" />
"use strict";
const AsymmetricEncryptionHelper_1 = require('../security/AsymmetricEncryptionHelper');
const chai_1 = require("chai");
describe('AsymmetricEncryptionHelper', () => {
    describe('#asymmetric en- and decryption', () => {
        it('should encrypt a data item using an asymmetric RSA key pair, and then decrypt it again, such that the decrypted data is the same as the input', (done) => {
            var data = "Hello World";
            var x = AsymmetricEncryptionHelper_1.AsymmetricEncryptionHelper.createKeyPair();
            var asymHelper = new AsymmetricEncryptionHelper_1.AsymmetricEncryptionHelper();
            var encryptedAsym = asymHelper.encryptStringWithRsaPublicKey(data, x.publicKey);
            var decryptedAsym = asymHelper.decryptStringWithRsaPrivateKey(encryptedAsym, x.privateKey);
            chai_1.assert(data === decryptedAsym, "input data is the same encrypted and decrypted input data");
            done();
        });
    });
});
//# sourceMappingURL=AsymmetricEncryptionHelperTest.js.map