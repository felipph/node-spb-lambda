
const SPBProtocol = require('../SPBProtocol.js');

describe("SPBProtocol", () => {
    const spbProtocol = new SPBProtocol('../sender.p12','123', '../receiver.p12','123');

    test('Header SPB', () => {
        console.log(spbProtocol.signAndEncrypt().toString('hex'));
        expect(1).toBe(1);
      });

})
