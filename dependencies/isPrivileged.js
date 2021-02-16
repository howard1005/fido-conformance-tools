const cp = require('child_process')

module.exports = () => {
    if(process.getuid) { // UNIX
        if(process.getuid() === 0) // ROOT
            return true
        else // Nah
            return false
    }else if(process.platform === 'win32') {
        try {
            cp.execSync('net session')
            return true
        } catch(e) {
            if(e.message.match( /Access is denied/ ))
                return false
            else
                throw new Error('Unknown error! The message is: ' + e);
        }
    } else
        throw new Error('Unsupported OS!');
}
