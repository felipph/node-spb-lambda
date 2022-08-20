import { SPBHeader } from "./spb/model/SPBHeader";


export interface SPBProtocol {

    header: SPBHeader;
    openContent: Uint8Array;
    inflatedContent: String;

    decryptSymetricKey(privateKey:Buffer): Buffer;

    decryptContents( encriptedContent: Buffer): Buffer;

    checkSignature(publicKey:Buffer):boolean;

    unpack(): String;


}