import { ProtocolError } from "../enums/ProtocolErrrors";

export class ProtocolException extends Error {
    
    readonly error: ProtocolError;    

    constructor(error: ProtocolError) {
        super(error);
    }

    getMessage(): String {
        return this.error;
    }


}