 // Import the requirements
 const openpgp = require('openpgp');

 module.exports = function(RED) {
  /* // Node for Sign a generic payload
   function GPG_Sign(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
      msg.debug=msg.privkey
      node.send(msg);
       var privKeyObj = openpgp.key.readArmored(msg.privkey).keys[0];

       privKeyObj.decrypt(msg.passphrase);

       options = {
         data: msg.payload.data, // input as String (or Uint8Array)
         privateKeys: privKeyObj // for signing
       };

       openpgp.sign(options).then(function(signed) {
         msg.payload.signature = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'
         node.status({
           fill: "green",
           shape: "dot",
           text: "Done"
         });

         delete msg['privkey'];
         delete msg['passphrase'];
         node.send(msg);
       });
     });
   }; // End of function
   // Node for Sign a generic payload
   function GPG_Sign_Verify(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
       //cleartext = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

       options = {
         message: openpgp.cleartext.readArmored(msg.payload.signature), // parse armored message
         publicKeys: openpgp.key.readArmored(msg.pubkey).keys // for verification
       };

       openpgp.verify(options).then(function(verified) {
         validity = verified.signatures[0].valid; // true
         if (validity) {
           console.log('signed by key id ' + verified.signatures[0].keyid
             .toHex());
           msg.status = "valid";
           node.status({
             fill: "green",
             shape: "dot",
             text: "Valid"
           });
         } else {
           msg.status = "not valid";
           node.status({
             fill: "red",
             shape: "dot",
             text: "Invalid"
           });
         }
         delete msg['pubkey'];
         node.send(msg);
       });

     });
   }; // End of function


   // Node for Sign a generic payload
   function GPG_Encrypt(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
       //cleartext = signed.data; // '-----BEGIN PGP SIGNED MESSAGE ... END PGP SIGNATURE-----'

       options = {
         message: openpgp.cleartext.readArmored(msg.payload.signature), // parse armored message
         publicKeys: openpgp.key.readArmored(msg.pubkey).keys // for verification
       };

       openpgp.verify(options).then(function(verified) {
         validity = verified.signatures[0].valid; // true
         if (validity) {
           console.log('signed by key id ' + verified.signatures[0].keyid
             .toHex());
           msg.status = "valid";
           node.status({
             fill: "green",
             shape: "dot",
             text: "Valid"
           });
         } else {
           msg.status = "not valid";
           node.status({
             fill: "red",
             shape: "dot",
             text: "Invalid"
           });
         }
         delete msg['pubkey'];
         node.send(msg);
       });

     });
   }; // End of function

   // Node for Sign a generic payload
   function GPG_Decrypt(n) {
     RED.nodes.createNode(this, n);
     this.status({
       fill: "grey",
       shape: "dot",
       text: "Waiting"
     });
     var node = this;
     this.on("input", function(msg) {
       options = {
         message: openpgp.cleartext.readArmored(msg.payload.signature), // parse armored message
         publicKeys: openpgp.key.readArmored(msg.pubkey).keys // for verification
       };

       openpgp.verify(options).then(function(verified) {
         validity = verified.signatures[0].valid; // true
         if (validity) {
           console.log('signed by key id ' + verified.signatures[0].keyid
             .toHex());
           msg.status = "valid";
           node.status({
             fill: "green",
             shape: "dot",
             text: "Valid"
           });
         } else {
           msg.status = "not valid";
           node.status({
             fill: "red",
             shape: "dot",
             text: "Invalid"
           });
         }
         delete msg['pubkey'];
         node.send(msg);
       });

     });
   }; // End of function


   // Register the node by name. This must be called before overriding any of the
   // Node functions.
   RED.nodes.registerType("GPG_Sign", GPG_Sign);
   RED.nodes.registerType(
     "GPG_Sign_Verify", GPG_Sign_Verify);
   RED.nodes.registerType("GPG_Encrypt", GPG_Encrypt);
   RED.nodes.registerType("GPG_Decrypt", GPG_Decrypt);*/

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
