// https://github.com/rzcoder/node-rsa


/* Notice: This lib supporting next hash algorithms:
 'md5', 'ripemd160', 'sha1', 'sha256', 'sha512' in browser and node environment
  and additional 'md4', 'sha', 'sha224', 'sha384' in node only. */
var NodeRSA = require('node-rsa');

var keypair = require('keypair');

var pair = keypair();

var key = new NodeRSA({b: 512});

console.log(key.keyPair);


var text = 'Hello RSA!';
var encrypted = key.encrypt(text, 'base64', 'utf-8');
console.log('encrypted: ', encrypted);
var decrypted = key.decrypt(encrypted, 'utf8');
console.log('decrypted: ', decrypted);