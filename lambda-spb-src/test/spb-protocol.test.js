
const SPBProtocol = require('../SPBProtocol.js');

describe("SPBProtocol", () => {
    const spbProtocol = new SPBProtocol('../sender.p12', '123', '../receiver.p12', '123');

    test('Encrypt', async () => {

        console.log(spbProtocol.signAndEncrypt("../req.xml"));
        expect(1).toBe(1);

    });


    test('Decrypt', async () => {

        console.log(spbProtocol.verifySignDecrypt('../req.gz.dat'));
        expect(1).toBe(1);
    });

})

