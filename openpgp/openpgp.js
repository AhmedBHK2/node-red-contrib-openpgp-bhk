 // Import the requirements
 const openpgp = require('openpgp');

 module.exports = function(RED) {

    // function PGP_Sign(config) {
    //     RED.nodes.createNode(this,config);
    //     var node = this;
    //     node.on('input', function(msg) {
    //         msg.payload = msg.payload.toLowerCase();
    //         node.send(msg);
    //     });
    // }

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
            //const serverPublicKeyArmored = decodeURIComponent(msg.encryption.serverPublicKey);
            const userPrivateKeyArmored = decodeURIComponent(msg.encryption.userPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);
            const encryptedMessage = decodeURIComponent(msg.encryption.encryptedMessage);
            console.log(encryptedMessage)
            //const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
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
            const serverPublicKeyArmored = decodeURIComponent(msg.encryption.serverPublicKey);
            const userPrivateKeyArmored = decodeURIComponent(msg.encryption.userPrivateKey);
            const passphrase = decodeURIComponent(msg.encryption.passphrase);

            const serverPublicKey = await openpgp.readKey({ armoredKey: serverPublicKeyArmored });
            const userPrivateKey = await openpgp.decryptKey({
                privateKey: await openpgp.readPrivateKey({ armoredKey: userPrivateKeyArmored }),
                passphrase
            });

            const readableText = msg.encryption.rawText
            
            const encrypted = await openpgp.encrypt({
                message: await openpgp.createMessage({ text: readableText }), // input as Message object
                encryptionKeys: serverPublicKey,
                signingKeys: userPrivateKey
            });
            msg.encrypted = encodeURIComponent(encrypted);
            node.send(msg);
        });
    }

    function PGP_DECRYPT_SIGNED(config) {
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
                expectSigned: true,
                verificationKeys: serverPublicKey,
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
