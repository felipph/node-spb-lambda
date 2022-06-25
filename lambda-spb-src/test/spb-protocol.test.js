
const SPBProtocol = require('../SPBProtocol.js');

describe("SPBProtocol", () => {
    const spbProtocol = new SPBProtocol('../sender.p12', '123', '../receiver.p12', '123');

    

    // test('Encrypt', () => {
    //     console.log(spbProtocol.signAndEncrypt("../req.xml"));
    //     expect(1).toBe(1);
    // });

    test('Decrypt', () => {
        console.log(spbProtocol.verifySignDecrypt('../resp.gz.dat'));
        expect(1).toBe(1);
    });

})

