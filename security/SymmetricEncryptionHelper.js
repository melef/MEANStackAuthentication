"use strict";
const crypto = require('crypto');
// http://lollyrock.com/articles/nodejs-encryption/
// (symmetric encrypt and decrypt text)
class SymmetricEncryptionHelper {
    constructor(algorithm, password) {
        this.algorithm = algorithm;
        this.password = password;
    }
    symmetricEncrypt(text) {
        var cipher = crypto.createCipher(this.algorithm, this.password);
        var crypted = cipher.update(text, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }
    symmetricDecrypt(text) {
        var decipher = crypto.createDecipher(this.algorithm, this.password);
        var dec = decipher.update(text, 'hex', 'utf8');
        dec += decipher.final('utf8');
        return dec;
    }
}
exports.SymmetricEncryptionHelper = SymmetricEncryptionHelper;
//# sourceMappingURL=SymmetricEncryptionHelper.js.map