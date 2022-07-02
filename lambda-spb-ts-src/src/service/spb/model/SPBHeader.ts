import { ProtocolVersion, ErrorCode, CryptAlgType, HashAlg, ContentEncryptionType } from "./enums/HeaderEnums";

export class SPBHeader {

    private static headerSize: number = 588;
    readonly protocolVersion: ProtocolVersion;
    readonly errorCode: ErrorCode;
    readonly assymetricAlgType: CryptAlgType;
    readonly symetricAlgType: ContentEncryptionType;
    readonly localAssymetricAlgType: ContentEncryptionType;
    readonly hashAlg: HashAlg;
    readonly serialCertDestination: String;
    readonly serialCertSource: String;
    readonly bufferEncryptedSymetricKey: Uint8Array;
    readonly bufferSignature: Buffer;

    constructor (headerBuffer:Buffer) {
        this.protocolVersion        = headerBuffer[2];
        this.errorCode              = headerBuffer[3];
        this.assymetricAlgType      = headerBuffer[6];
        this.symetricAlgType        = headerBuffer[7];
        this.localAssymetricAlgType = headerBuffer[8];
        this.hashAlg                = headerBuffer[9];

        //alocando 32 bytes para pegar o serial do certificado
        var sharedBuffer = Buffer.alloc(32)
        for( var i = 11 ; i < 43; i++) {
            sharedBuffer[i-11] = headerBuffer[i];
        }
        this.serialCertDestination = sharedBuffer.toString('utf8');

        //usando o mesmo buffer para ler o certificado da origem
        for( var i = 44 ; i < 76; i++) {
            sharedBuffer[i-44] = headerBuffer[i];
        }        
        this.serialCertSource = sharedBuffer.toString('utf8');

        sharedBuffer = Buffer.alloc(256)
        for( var i = 76 ; i < 332; i++) {
            sharedBuffer[i-76] = headerBuffer[i];
        }
        this.bufferEncryptedSymetricKey = sharedBuffer;
        
        sharedBuffer = Buffer.alloc(256)
        for( var i = 332 ; i < 588; i++) {
            sharedBuffer[i-332] = headerBuffer[i];
        }
        this.bufferSignature = sharedBuffer;

        sharedBuffer = null; //setando nulo para liberar memoria
        headerBuffer = null; //setando nulo para liberar memoria

        if(ProtocolVersion[this.protocolVersion] == null ) {
            throw new Error("Protocolo Inválido!")
        }
    }

    public static getHeaderSize():number {
        return SPBHeader.headerSize;
    }

    private validate():void {
        /**
         * TODO: montar a validação do header
         */
    }
}