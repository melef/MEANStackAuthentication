//Example for Public/Private Key taken from
//https://github.com/rzcoder/node-rsa
//https://www.npmjs.com/package/keypair for RSA key pairs
"use strict";
var crypto = require('crypto');
var nodeforge = require('node-forge');
var AsymmetricEncryptionHelper = (function () {
    function AsymmetricEncryptionHelper() {
    }
    AsymmetricEncryptionHelper.prototype.encryptStringWithRsaPublicKey = function (textToEncrypt, publicKey) {
        var buffer = new Buffer(textToEncrypt);
        var encrypted = crypto.publicEncrypt(publicKey, buffer);
        return encrypted.toString("base64");
    };
    AsymmetricEncryptionHelper.prototype.decryptStringWithRsaPrivateKey = function (textToDecrypt, privateKey) {
        var buffer = new Buffer(textToDecrypt, "base64");
        var decrypted = crypto.privateDecrypt(privateKey, buffer);
        return decrypted.toString("utf8");
    };
    AsymmetricEncryptionHelper.createKeyPair = function () {
        var pair = nodeforge.pki.rsa.generateKeyPair();
        var publicKey = nodeforge.pki.publicKeyToPem(pair.publicKey);
        var privateKey = nodeforge.pki.privateKeyToPem(pair.privateKey);
        return { "privateKey": privateKey, "publicKey": publicKey };
    };
    return AsymmetricEncryptionHelper;
}());
exports.AsymmetricEncryptionHelper = AsymmetricEncryptionHelper;
