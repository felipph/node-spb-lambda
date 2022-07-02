import { SPBProtocol } from "../../SPBProtocol";
import { SPBHeader } from "../model/SPBHeader";
import * as crypto from "crypto"
import * as zlib from "zlib"


export class SPBProtocolV2 implements SPBProtocol {

    header: SPBHeader;
    content: Buffer;
    symetricKey: Buffer;
    inflatedContent: String;

    constructor(private encriptedContent: Buffer, header: SPBHeader) {
        this.header = header;
    }

    decryptSymetricKey(privateKey: Buffer): Buffer {

        this.symetricKey = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_PADDING
            },
            this.header.bufferEncryptedSymetricKey);
        return this.symetricKey;
    }


    checkSignature(publicKey: Buffer): boolean {
        if (this.content == null) {
            throw new Error("Primeiro é necessário depriptar o conteúdo!")
        }
        var verifier = crypto.createVerify("SHA256");
        verifier.update(this.content)
        return verifier.verify(publicKey,this.header.bufferSignature);
    }
    decryptContents(): Buffer {
        if(this.symetricKey == null) {
            throw new Error('Chave Simétrica não disponível!');
        }        
        const decipher3des = crypto.createDecipheriv('des-ede3-cbc', this.symetricKey, this.symetricKey.slice(0,8))
        decipher3des.setAutoPadding(false)
        var decrypted = decipher3des.update(this.encriptedContent)
        this.content = Buffer.concat([decrypted,decipher3des.final()]);
        return this.content;
    }

    unpack(): String {
        this.inflatedContent = zlib.gunzipSync(this.content).toString('utf-8');
        return this.inflatedContent;
    }

}