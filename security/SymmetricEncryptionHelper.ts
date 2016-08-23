import crypto = require('crypto');
import nodeforge = require('node-forge');


// http://lollyrock.com/articles/nodejs-encryption/
// (symmetric encrypt and decrypt text)
export class SymmetricEncryptionHelper {


    static symmetricEncrypt(text: string, algorithm: string, password: string): string {
        var cipher = crypto.createCipher(algorithm, password)
        var crypted = cipher.update(text, 'utf8', 'hex')
        crypted += cipher.final('hex');
        return crypted;
    }

    static symmetricDecrypt(text: string, algorithm: string, password: string): string {
        var decipher = crypto.createDecipher( algorithm, password)
        var dec = decipher.update(text, 'hex', 'utf8')
        dec += decipher.final('utf8');
        return dec;
    }
}