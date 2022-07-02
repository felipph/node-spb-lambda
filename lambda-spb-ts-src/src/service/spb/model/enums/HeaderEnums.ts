export enum HashAlg {
    SHA1    = 0x02,
    SHA256  = 0x03
}

export enum  ProtocolVersion {
    V1 = 0x00,
    V2 = 0x02,
    V3 = 0x03
};

export enum ErrorCode {
    OK       = 0x00, //OK
    EGEN9901 = 0x01 //Tamanho do cabeçalho de segurança zerado ou incompatível com os possíveis
}

export enum CryptAlgType {
    RSA_1028 = 0x01,
    RSA_2048 = 0x02
}

export enum ContentEncryptionType {
    TripleDES = 0x01,
    AES       = 0x02
}
