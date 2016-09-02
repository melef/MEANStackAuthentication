"use strict";
const crypto = require('crypto');
// http://lollyrock.com/articles/nodejs-encryption/
// (symmetric encrypt and decrypt text)
class SymmetricEncryptionHelper {
    static symmetricEncrypt(text, algorithm, encryptionkey) {
        var cipher = crypto.createCipher(algorithm, encryptionkey);
        var crypted = cipher.update(text, 'utf8', 'hex');
        crypted += cipher.final('hex');
        return crypted;
    }
    static symmetricDecrypt(text, algorithm, encryptionkey) {
        var decipher = crypto.createDecipher(algorithm, encryptionkey);
        var dec = decipher.update(text, 'hex', 'utf8');
        dec += decipher.final('utf8');
        return dec;
    }
}
exports.SymmetricEncryptionHelper = SymmetricEncryptionHelper;
//# sourceMappingURL=SymmetricEncryptionHelper.js.map