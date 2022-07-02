"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContentEncryptionType = exports.CryptAlgType = exports.ErrorCode = exports.ProtocolVersion = exports.HashAlg = void 0;
var HashAlg;
(function (HashAlg) {
    HashAlg[HashAlg["SHA1"] = 2] = "SHA1";
    HashAlg[HashAlg["SHA256"] = 3] = "SHA256";
})(HashAlg = exports.HashAlg || (exports.HashAlg = {}));
var ProtocolVersion;
(function (ProtocolVersion) {
    ProtocolVersion[ProtocolVersion["V1"] = 0] = "V1";
    ProtocolVersion[ProtocolVersion["V2"] = 2] = "V2";
    ProtocolVersion[ProtocolVersion["V3"] = 3] = "V3";
})(ProtocolVersion = exports.ProtocolVersion || (exports.ProtocolVersion = {}));
;
var ErrorCode;
(function (ErrorCode) {
    ErrorCode[ErrorCode["OK"] = 0] = "OK";
    ErrorCode[ErrorCode["EGEN9901"] = 1] = "EGEN9901"; //Tamanho do cabeçalho de segurança zerado ou incompatível com os possíveis
})(ErrorCode = exports.ErrorCode || (exports.ErrorCode = {}));
var CryptAlgType;
(function (CryptAlgType) {
    CryptAlgType[CryptAlgType["RSA_1028"] = 1] = "RSA_1028";
    CryptAlgType[CryptAlgType["RSA_2048"] = 2] = "RSA_2048";
})(CryptAlgType = exports.CryptAlgType || (exports.CryptAlgType = {}));
var ContentEncryptionType;
(function (ContentEncryptionType) {
    ContentEncryptionType[ContentEncryptionType["TripleDES"] = 1] = "TripleDES";
    ContentEncryptionType[ContentEncryptionType["AES"] = 2] = "AES";
})(ContentEncryptionType = exports.ContentEncryptionType || (exports.ContentEncryptionType = {}));
//# sourceMappingURL=HeaderEnums.js.map