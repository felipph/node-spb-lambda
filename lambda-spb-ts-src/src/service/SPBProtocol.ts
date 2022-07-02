import { SPBHeader } from "./spb/model/SPBHeader";


export interface SPBProtocol {

    header: SPBHeader;
    content: Uint8Array;
    inflatedContent: String;

    decryptSymetricKey(privateKey:Buffer): Buffer;

    decryptContents( symetricKey: Buffer): Buffer;

    checkSignature(publicKey:Buffer):boolean;

    unpack(): String;


}