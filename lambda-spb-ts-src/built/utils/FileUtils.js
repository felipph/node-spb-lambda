"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileUtils = void 0;
const fs = require("fs");
class FileUtils {
    static readBytes(fd, sharedBuffer, offset) {
        return new Promise((resolve, reject) => {
            fs.read(fd, sharedBuffer, 0, sharedBuffer.length, offset, (err) => {
                if (err) {
                    return reject(err);
                }
                resolve();
            });
        });
    }
}
exports.FileUtils = FileUtils;
//# sourceMappingURL=FileUtils.js.map