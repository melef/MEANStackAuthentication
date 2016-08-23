//Example for Public/Private Key taken from
//https://github.com/rzcoder/node-rsa
//https://www.npmjs.com/package/keypair for RSA key pairs

import crypto = require('crypto');
import nodeforge = require('node-forge');

export class AsymmetricEncryptionHelper {

   static encryptStringWithRsaPublicKey(textToEncrypt: string, publicKey: string): string {
        var buffer = new Buffer(textToEncrypt);
        var encrypted = crypto.publicEncrypt(publicKey, buffer);
        return encrypted.toString("base64");
    }

    static decryptStringWithRsaPrivateKey(textToDecrypt: string, privateKey: string): string {
        var buffer = new Buffer(textToDecrypt, "base64");
        var decrypted = crypto.privateDecrypt(privateKey, buffer);
        return decrypted.toString("utf8");
    }

    static createKeyPair() {
        var pair = nodeforge.pki.rsa.generateKeyPair();
        var publicKey = nodeforge.pki.publicKeyToPem(pair.publicKey);
        var privateKey = nodeforge.pki.privateKeyToPem(pair.privateKey);
        return {"privateKey": privateKey, "publicKey": publicKey};
    }
}

