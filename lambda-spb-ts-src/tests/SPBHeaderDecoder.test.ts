import { SPBHeaderDecoder } from "../src/lib/spb/SPBHeaderDecoder";
import {expect, jest, test, describe} from '@jest/globals';
import { ProtocolException } from "../src/lib/spb/exception/ProtocolException";
import { ProtocolError } from "../src/lib/spb/enums/ProtocolErrrors";


function getBaseHeader():Buffer {
    const HEADER_SIZE = 588;
        let buff = Buffer.alloc(HEADER_SIZE)
        buff.writeIntBE(HEADER_SIZE, 0, 2) //C1
        var offset = 2;
        buff.writeIntBE(2, offset++, 1); // c02 - Protocol Version        
        buff.writeIntBE(0, offset++, 1); // c03 - Error Code
        buff.writeIntBE(8, offset++, 1); // c04 - Special Treatment Indicator:
        buff.writeIntBE(0, offset++, 1); // c05 - Reservado
        buff.writeIntBE(2, offset++, 1); // C06 - destAsymmetricAlgorithm:
        buff.writeIntBE(1, offset++, 1); // C07 - symmetricAlgorithm:
        buff.writeIntBE(2, offset++, 1); // C08 - asymmetricAlgorithm :
        buff.writeIntBE(3, offset++, 1); // C09 - hashAlgorithm: 02H: SHA-1, 03H: SHA-256
        buff.writeIntBE(4, offset++, 1); // C10 - destCertCa:
        buff.write("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", offset++, 32); // C11 - destination Certificate Serial Number
        offset = offset + 31;
        buff.writeIntBE(4, offset++, 1); // C12 - signatureCertCa
        buff.write("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", offset++, 32); // C13 - signature Certificate Serial Number - Local
        return buff;
}

describe("SPBHeaderDecoder", () => {
   
    test('Versão do Procolo inválido!', async () => {     
        let buff = getBaseHeader();
        buff.writeIntBE(5, 2, 1); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9902));
    });

    test('Tamanho do header inválido!', async () => {
        let buff = getBaseHeader();
        buff.writeIntBE(500, 0, 2); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9901));
    });

    test('Algoritimo da chave assimétrica de destino inválida', async () => {
        let buff = getBaseHeader();
        buff.writeIntBE(5, 6, 1); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9903));
    });

    test('Algoritimo simétrico inválido', async () => {
        let buff = getBaseHeader();
        buff.writeIntBE(5, 7, 1); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9904));
    });

    test('Algoritimo da chave assimétrica de origem inválido', async () => {
        let buff = getBaseHeader();
        buff.writeIntBE(5, 8, 1); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9905));
    });

    test('Algoritimo de HASH inválido', async () => {
        let buff = getBaseHeader();
        buff.writeIntBE(5, 9, 1); 
        expect(() => new SPBHeaderDecoder(buff)).toThrow(new ProtocolException(ProtocolError.EGEN9906));
    });
})