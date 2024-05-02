 // Import the requirements
 const openpgp = require('openpgp');

 module.exports = function(RED) {

    function PGP_Sign(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', function(msg) {
            msg.payload = msg.payload.toLowerCase();
            node.send(msg);
        });
    }

    function PGP_ENCRYPT(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const serverPublicKeyArmored = decodeURIComponent(msg.encryption.serverPublicKey);
            const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
            const readableText = msg.encryption.rawText
            const encrypted = await openpgp.encrypt({
                message: await openpgp.createMessage({ text: readableText }), // input as Message object
                encryptionKeys: serverPublicKey
            });
            msg.encrypted = encodeURIComponent(encrypted);
            node.send(msg);
        });
    }


    function PGP_DECRYPT(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const serverPublicKeyArmored = decodeURIComponent(msg.encryption.serverPublicKey);
            const userPrivateKeyArmored = decodeURIComponent(msg.encryption.userPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);
            const encryptedMessage = decodeURIComponent(msg.encryption.encryptedMessage);
            console.log(encryptedMessage)
            const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
            const userPrivateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: userPrivateKeyArmored }),
                passphrase
            });
            
            const message = await openpgp.readMessage({
                armoredMessage: encryptedMessage // parse armored message
            });

            const { data: decrypted, signatures } = await openpgp.decrypt({
                message,
                decryptionKeys: userPrivateKey,
            });
            msg.decrypted = encodeURIComponent(encrypted);
            node.send(msg);
        });
    }

    RED.nodes.registerType("PGP_SIGN",PGP_Sign);
    RED.nodes.registerType("PGP_ENCRYPT",PGP_ENCRYPT);
    RED.nodes.registerType("PGP_DECRYPT",PGP_DECRYPT);
 }
