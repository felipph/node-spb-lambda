"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SPBProtocolV2 = void 0;
const crypto = require("crypto");
const zlib = require("zlib");
class SPBProtocolV2 {
    constructor(encriptedContent, header) {
        this.encriptedContent = encriptedContent;
        this.header = header;
    }
    decryptSymetricKey(privateKey) {
        this.symetricKey = crypto.privateDecrypt({
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING
        }, this.header.bufferEncryptedSymetricKey);
        return this.symetricKey;
    }
    checkSignature(publicKey) {
        if (this.content == null) {
            throw new Error("Primeiro é necessário depriptar o conteúdo!");
        }
        var verifier = crypto.createVerify("SHA256");
        verifier.update(this.content);
        return verifier.verify(publicKey, this.header.bufferSignature);
    }
    decryptContents() {
        if (this.symetricKey == null) {
            throw new Error('Chave Simétrica não disponível!');
        }
        const decipher3des = crypto.createDecipheriv('des-ede3-cbc', this.symetricKey, this.symetricKey.slice(0, 8));
        decipher3des.setAutoPadding(false);
        var decrypted = decipher3des.update(this.encriptedContent);
        this.content = Buffer.concat([decrypted, decipher3des.final()]);
        return this.content;
    }
    unpack() {
        this.inflatedContent = zlib.gunzipSync(this.content).toString('utf-8');
        return this.inflatedContent;
    }
}
exports.SPBProtocolV2 = SPBProtocolV2;
//# sourceMappingURL=SPBProtocolV2.js.map