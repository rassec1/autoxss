class EncodingHandler {
    constructor() {
        this.encodings = {
            url: /%[0-9A-Fa-f]{2}/,
            html: /&[a-zA-Z]+;/,
            js: /\\u[0-9A-Fa-f]{4}/,
            unicode: /&#x?[0-9A-Fa-f]+;/,
            base64: /^[A-Za-z0-9+/=]+$/
        };
    }

    handleEncoding(input, environment) {
        const detectedEncodings = this.detectEncodings(input);
        let processedInput = input;

        for (const encoding of detectedEncodings) {
            switch(encoding) {
                case 'url':
                    processedInput = this.handleUrlEncoding(processedInput);
                    break;
                case 'html':
                    processedInput = this.handleHtmlEncoding(processedInput);
                    break;
                case 'js':
                    processedInput = this.handleJsEncoding(processedInput);
                    break;
                case 'unicode':
                    processedInput = this.handleUnicodeEncoding(processedInput);
                    break;
                case 'base64':
                    processedInput = this.handleBase64Encoding(processedInput);
                    break;
            }
        }

        return processedInput;
    }

    detectEncodings(input) {
        const detected = [];
        
        // 检查URL编码
        if (this.encodings.url.test(input)) {
            detected.push('url');
        }
        
        // 检查HTML编码
        if (this.encodings.html.test(input)) {
            detected.push('html');
        }
        
        // 检查JavaScript编码
        if (this.encodings.js.test(input)) {
            detected.push('js');
        }
        
        // 检查Unicode编码
        if (this.encodings.unicode.test(input)) {
            detected.push('unicode');
        }
        
        // 检查Base64编码
        if (this.encodings.base64.test(input)) {
            detected.push('base64');
        }

        return detected;
    }

    handleUrlEncoding(input) {
        try {
            return decodeURIComponent(input);
        } catch (e) {
            return input;
        }
    }

    handleHtmlEncoding(input) {
        const htmlEntities = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#039;': "'",
            '&nbsp;': ' '
        };

        return input.replace(/&[a-zA-Z]+;/g, match => htmlEntities[match] || match);
    }

    handleJsEncoding(input) {
        return input.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => 
            String.fromCharCode(parseInt(hex, 16))
        );
    }

    handleUnicodeEncoding(input) {
        return input.replace(/&#x?([0-9A-Fa-f]+);/g, (_, hex) => 
            String.fromCharCode(parseInt(hex, 16))
        );
    }

    handleBase64Encoding(input) {
        try {
            return atob(input);
        } catch (e) {
            return input;
        }
    }

    validateEncodedPayload(encodedInput, response) {
        // 检查响应中是否包含解码后的payload
        const decodedPayload = this.handleEncoding(encodedInput, {});
        return response.includes(decodedPayload);
    }

    // 生成不同编码的payload变体
    generateEncodedVariants(payload) {
        const variants = [];

        // URL编码变体
        variants.push(encodeURIComponent(payload));
        variants.push(encodeURI(payload));

        // HTML编码变体
        variants.push(payload.replace(/[&<>"']/g, char => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        })[char]));

        // JavaScript编码变体
        variants.push(payload.split('').map(char => 
            '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')
        ).join(''));

        // Unicode编码变体
        variants.push(payload.split('').map(char => 
            '&#x' + char.charCodeAt(0).toString(16) + ';'
        ).join(''));

        // Base64编码变体
        variants.push(btoa(payload));

        return variants;
    }
}

export const encodingHandler = new EncodingHandler(); 