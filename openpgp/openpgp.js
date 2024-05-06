 // Import the requirements
 const openpgp = require('openpgp');

 module.exports = function(RED) {

    function PGP_ENCRYPT(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const receiverPublicKeyArmored = decodeURIComponent(msg.encryption.receiverPublicKey);
            const receiverPublicKey = await openpgp.readKey({ armoredKey: receiverPublicKeyArmored });
            const readableText = msg.encryption.rawText
            const encrypted = await openpgp.encrypt({
                message: await openpgp.createMessage({ text: readableText }), // input as Message object
                encryptionKeys: receiverPublicKey
            });
            msg.encrypted = encodeURIComponent(encrypted);
            node.send(msg);
        });
    }


    function PGP_DECRYPT(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            //const serverPublicKeyArmored = decodeURIComponent(msg.encryption.serverPublicKey);
            const receiverPrivateKeyArmored = decodeURIComponent(msg.encryption.receiverPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);
            const encryptedMessage = decodeURIComponent(msg.encryption.encryptedMessage);
            
            //console.log(encryptedMessage)
            //const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
            const receiverPrivateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: receiverPrivateKeyArmored }),
                passphrase
            });
            
            
            const message = await openpgp.readMessage({
                armoredMessage: encryptedMessage // parse armored message
            });

            //console.log(receiverPrivateKey)
            //console.log("-------------------------------------------------------")
            const { data: decrypted } = await openpgp.decrypt({
                message,
                decryptionKeys: receiverPrivateKey,
                expectSigned: false
            });
            msg.decrypted = encodeURIComponent(decrypted);
            node.send(msg);
        });
    }

    function PGP_GENERATE_KEY_PAIR(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const name = decodeURIComponent(msg.encryption.name);
            const email = decodeURIComponent(msg.encryption.email);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);
            
            var options = {
                userIDs: [{ name:name, email:email }], // multiple user IDs
                passphrase: passphrase         // protects the private key
            };


            const {publicKey, privateKey} = await openpgp.generateKey(options);
            msg.keyPair = {publicKey, privateKey}
            node.send(msg);
        });
    }

    function PGP_ENCRYPT_SIGN(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const receiverPublicKeyArmored = decodeURIComponent(msg.encryption.receiverPublicKey);
            const senderPrivateKeyArmored = decodeURIComponent(msg.encryption.senderPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);

            const receiverPublicKey = await openpgp.readKey({ armoredKey: receiverPublicKeyArmored });
            const senderPrivateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: senderPrivateKeyArmored }),
                passphrase
            });

            const readableText = msg.encryption.rawText
            
            const encrypted = await openpgp.encrypt({
                message: await openpgp.createMessage({ text: readableText }), // input as Message object
                encryptionKeys: receiverPublicKey,
                signingKeys: senderPrivateKey
            });
            msg.encrypted = encodeURIComponent(encrypted);
            node.send(msg);
        });
    }

    function PGP_DECRYPT_SIGNED(config) {
        RED.nodes.createNode(this,config);
        var node = this;
        node.on('input', async function(msg) {
            const senderPublicKeyArmored = decodeURIComponent(msg.encryption.senderPublicKey);
            const receiverPrivateKeyArmored = decodeURIComponent(msg.encryption.receiverPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);
            const encryptedMessage = decodeURIComponent(msg.encryption.encryptedMessage);
            //console.log(senderPublicKeyArmored)
            const senderPublicKey = await openpgp.readKey({ armoredKey: senderPublicKeyArmored });
                        //console.log("-------------------------------------*********************************----------------")

            const receiverPrivateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: receiverPrivateKeyArmored }),
                passphrase
            });
            const message = await openpgp.readMessage({
                armoredMessage: encryptedMessage // parse armored message
            });


            const { data: decrypted, signatures } = await openpgp.decrypt({
                message,
                decryptionKeys: receiverPrivateKey,
                expectSigned: true,
                verificationKeys: senderPublicKey,
            });
            msg.decrypted = encodeURIComponent(decrypted);
            node.send(msg);
        });
    }

    RED.nodes.registerType("PGP_GENERATE_KEY_PAIR",PGP_GENERATE_KEY_PAIR);
    RED.nodes.registerType("PGP_ENCRYPT",PGP_ENCRYPT);
    RED.nodes.registerType("PGP_DECRYPT",PGP_DECRYPT);
    RED.nodes.registerType("PGP_ENCRYPT_SIGN",PGP_ENCRYPT_SIGN);
    RED.nodes.registerType("PGP_DECRYPT_SIGNED",PGP_DECRYPT_SIGNED);
 }
