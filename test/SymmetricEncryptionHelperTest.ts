/// <reference path="../typings/globals/mocha/index.d.ts" />
//see also node-rsa
import {SymmetricEncryptionHelper}  from '../security/SymmetricEncryptionHelper';
import {assert} from "chai";

describe('SymmetricEncryptionHelper', ()=> {
    describe('#symmetric', ()=> {
        var data = "Hello World";
        var password = "1234";
        var algorithm = "aes-256-ctr"; //encryption with ctr --> see other algorithms in the link in CryptographyProvider


        it('should encrypt a data item using a symmetric key and the decrypted data item should be the same as the input data item', (done)=> {
            var encryptedSym = SymmetricEncryptionHelper.symmetricEncrypt(data, algorithm, password);
            var decryptedSym = SymmetricEncryptionHelper.symmetricDecrypt(data, algorithm, password);
            assert(data === decryptedSym, "input data is the same encrypted and decrypted input data");
            done();
        });
    });
});
