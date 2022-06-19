var fs = require('fs');


module.exports = class FileUtils {
    getFile(filePath){
        return fs.readFileSync(filePath, 'binary');
    }
}