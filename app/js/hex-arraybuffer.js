(function () {
    /**
     * hex-to-array-buffer - Turn a string of hexadecimal characters into an `ArrayBuffer`
     * @version v0.1.0
     * @license MIT
     * @copyright Linus <linus@folkdatorn.se> Unnebäck
     * @link https://github.com/LinusU/hex-to-array-buffer/
     */
    let hexToArrayBuffer = (hex) => {
        if (typeof hex !== 'string') {
            throw new TypeError('Expected input to be a string')
        }

        if ((hex.length % 2) !== 0) {
            throw new RangeError('Expected string to be an even number of characters')
        }

        var view = new Uint8Array(hex.length / 2)

        for (var i = 0; i < hex.length; i += 2) {
            view[i / 2] = parseInt(hex.substring(i, i + 2), 16)
        }

        return view
    }

    let arrayBufferToHex = (buffer) => {
        return Array.prototype.map
            .call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2))
            .join('');
    }

    let methods = {
        'decode': hexToArrayBuffer,
        'encode': arrayBufferToHex
    }

    /**
     * Exporting and stuff
     */
    if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
        module.exports = methods;
    } else {
        if (typeof define === 'function' && define.amd) {
            define([], function() {
                return methods;
            });
        } else {
            window.hex = methods;
        }
    }
})()
