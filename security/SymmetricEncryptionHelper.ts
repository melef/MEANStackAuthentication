import crypto = require('crypto');
import nodeforge = require('node-forge');


// http://lollyrock.com/articles/nodejs-encryption/
// (symmetric encrypt and decrypt text)
export class SymmetricEncryptionHelper {

    algorithm: string;
    password: string;

    constructor(algorithm: string, password: string) {
        this.algorithm = algorithm;
        this.password = password;
    }

    symmetricEncrypt(text: string): string {
        var cipher = crypto.createCipher(this.algorithm, this.password)
        var crypted = cipher.update(text, 'utf8', 'hex')
        crypted += cipher.final('hex');
        return crypted;
    }

    symmetricDecrypt(text: string): string {
        var decipher = crypto.createDecipher(this.algorithm, this.password)
        var dec = decipher.update(text, 'hex', 'utf8')
        dec += decipher.final('utf8');
        return dec;
    }
}