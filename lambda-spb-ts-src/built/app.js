"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const SPBHeader_1 = require("./service/spb/model/SPBHeader");
const FileUtils_1 = require("./utils/FileUtils");
const SPBProtocolV2_1 = require("./service/spb/impl/SPBProtocolV2");
async function main() {
    const filePath = '../req.gz.dat';
    const fd = fs.openSync(filePath, 'r'); // file descriptor
    const stats = fs.statSync(filePath); // file details
    var sharedBuffer = Buffer.alloc(SPBHeader_1.SPBHeader.getHeaderSize());
    //carregando somente o header    
    await FileUtils_1.FileUtils.readBytes(fd, sharedBuffer);
    var header = new SPBHeader_1.SPBHeader(sharedBuffer);
    console.log(header);
    var contentSize = stats.size - SPBHeader_1.SPBHeader.getHeaderSize();
    sharedBuffer = Buffer.alloc(contentSize);
    await FileUtils_1.FileUtils.readBytes(fd, sharedBuffer, 588);
    const protocol = new SPBProtocolV2_1.SPBProtocolV2(sharedBuffer, header);
    var publicKey = fs.readFileSync("./certDestino/publicKeyDestino.pem");
    var privateKey = fs.readFileSync("./certDestino/privateKeyDestino.pem");
    const symetricKey = protocol.decryptSymetricKey(privateKey);
    console.log(symetricKey.toString('utf-8'));
    protocol.decryptContents();
    var publicKeyOrigem = fs.readFileSync("./certOrigem/publicKeyOrigem.pem");
    if (!protocol.checkSignature(publicKeyOrigem)) {
        console.log("Assinatura inválida!");
    }
    console.log(protocol.unpack());
}
main().then((ok) => {
    const used = process.memoryUsage();
    for (let key in used) {
        console.log(`${key} ${Math.round(used[key] / 1024 / 1024 * 100)} KB`);
    }
});
//# sourceMappingURL=app.js.map