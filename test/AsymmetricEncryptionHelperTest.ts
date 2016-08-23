/// <reference path="../typings/globals/mocha/index.d.ts" />

import {AsymmetricEncryptionHelper}  from '../security/AsymmetricEncryptionHelper';
import {assert} from "chai";

describe('AsymmetricEncryptionHelper', ()=> {
    describe('#asymmetric en- and decryption', ()=> {
        it('should encrypt a data item using an asymmetric RSA key pair, and then decrypt it again, such that the decrypted data is the same as the input', (done)=> {
            var data = "Hello World";
            var x = AsymmetricEncryptionHelper.createKeyPair();
             var encryptedAsym = AsymmetricEncryptionHelper.encryptStringWithRsaPublicKey(data, x.publicKey);
            var decryptedAsym = AsymmetricEncryptionHelper.decryptStringWithRsaPrivateKey(encryptedAsym, x.privateKey);
            assert(data === decryptedAsym, "input data is the same encrypted and decrypted input data");
            done();
        });
    });
});
