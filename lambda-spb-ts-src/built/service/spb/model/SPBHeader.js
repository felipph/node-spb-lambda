"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SPBHeader = void 0;
const HeaderEnums_1 = require("./enums/HeaderEnums");
class SPBHeader {
    constructor(headerBuffer) {
        this.protocolVersion = headerBuffer[2];
        this.errorCode = headerBuffer[3];
        this.assymetricAlgType = headerBuffer[6];
        this.symetricAlgType = headerBuffer[7];
        this.localAssymetricAlgType = headerBuffer[8];
        this.hashAlg = headerBuffer[9];
        //alocando 32 bytes para pegar o serial do certificado
        var sharedBuffer = Buffer.alloc(32);
        for (var i = 11; i < 43; i++) {
            sharedBuffer[i - 11] = headerBuffer[i];
        }
        this.serialCertDestination = sharedBuffer.toString('utf8');
        //usando o mesmo buffer para ler o certificado da origem
        for (var i = 44; i < 76; i++) {
            sharedBuffer[i - 44] = headerBuffer[i];
        }
        this.serialCertSource = sharedBuffer.toString('utf8');
        sharedBuffer = Buffer.alloc(256);
        for (var i = 76; i < 332; i++) {
            sharedBuffer[i - 76] = headerBuffer[i];
        }
        this.bufferEncryptedSymetricKey = sharedBuffer;
        sharedBuffer = Buffer.alloc(256);
        for (var i = 332; i < 588; i++) {
            sharedBuffer[i - 332] = headerBuffer[i];
        }
        this.bufferSignature = sharedBuffer;
        sharedBuffer = null; //setando nulo para liberar memoria
        headerBuffer = null; //setando nulo para liberar memoria
        if (HeaderEnums_1.ProtocolVersion[this.protocolVersion] == null) {
            throw new Error("Protocolo Inválido!");
        }
    }
    static getHeaderSize() {
        return SPBHeader.headerSize;
    }
    validate() {
        /**
         * TODO: montar a validação do header
         */
    }
}
exports.SPBHeader = SPBHeader;
SPBHeader.headerSize = 588;
//# sourceMappingURL=SPBHeader.js.map