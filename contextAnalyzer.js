class ContextAnalyzer {
    constructor() {
        // 定义不同上下文的特征模式
        this.contexts = {
            html: {
                patterns: [
                    /<[^>]*>/g,  // HTML标签
                    /&[a-zA-Z]+;/g,  // HTML实体
                    /&#x?[0-9a-fA-F]+;/g  // HTML数字实体
                ],
                attributes: [
                    'href', 'src', 'onerror', 'onload', 'onclick',
                    'onmouseover', 'onmouseout', 'onkeypress',
                    'onkeydown', 'onkeyup', 'onfocus', 'onblur'
                ]
            },
            javascript: {
                patterns: [
                    /<script[^>]*>[\s\S]*?<\/script>/gi,  // 脚本标签
                    /javascript:/i,  // JavaScript协议
                    /on\w+\s*=/i,  // 事件处理器
                    /eval\s*\(/i,  // eval函数
                    /Function\s*\(/i,  // Function构造函数
                    /setTimeout\s*\(/i,  // setTimeout
                    /setInterval\s*\(/i  // setInterval
                ],
                attributes: [
                    'onerror', 'onload', 'onclick', 'onmouseover',
                    'onmouseout', 'onkeypress', 'onkeydown', 'onkeyup'
                ]
            },
            css: {
                patterns: [
                    /<style[^>]*>[\s\S]*?<\/style>/gi,  // 样式标签
                    /style\s*=\s*["'][^"']*["']/i,  // 内联样式
                    /url\s*\(/i,  // url()函数
                    /expression\s*\(/i,  // expression()函数
                    /@import/i  // @import规则
                ],
                attributes: ['style']
            }
        };

        // 定义常见的净化方法
        this.sanitizationMethods = {
            html: {
                patterns: [
                    /htmlspecialchars/i,
                    /htmlentities/i,
                    /strip_tags/i,
                    /sanitize/i
                ],
                functions: [
                    'escapeHTML',
                    'sanitizeHTML',
                    'cleanHTML',
                    'purifyHTML'
                ]
            },
            javascript: {
                patterns: [
                    /escape\s*\(/i,
                    /encodeURI\s*\(/i,
                    /encodeURIComponent\s*\(/i,
                    /sanitize\s*\(/i
                ],
                functions: [
                    'escapeJS',
                    'sanitizeJS',
                    'cleanJS',
                    'purifyJS'
                ]
            },
            css: {
                patterns: [
                    /sanitize\s*\(/i,
                    /clean\s*\(/i,
                    /purify\s*\(/i
                ],
                functions: [
                    'sanitizeCSS',
                    'cleanCSS',
                    'purifyCSS'
                ]
            }
        };
    }

    // 分析上下文
    analyzeContext(element) {
        const analysis = {
            type: null,
            location: null,
            sanitization: null,
            encoding: null,
            parentContext: null,
            recommendations: []
        };

        // 检测上下文类型
        analysis.type = this.detectContextType(element);

        // 分析位置
        analysis.location = this.analyzeLocation(element);

        // 检测净化方法
        analysis.sanitization = this.detectSanitization(element);

        // 分析编码
        analysis.encoding = this.analyzeEncoding(element);

        // 分析父上下文
        analysis.parentContext = this.analyzeParentContext(element);

        // 生成建议
        analysis.recommendations = this.generateRecommendations(analysis);

        return analysis;
    }

    // 检测上下文类型
    detectContextType(element) {
        const types = [];

        // 检查HTML上下文
        if (this.checkHTMLContext(element)) {
            types.push('html');
        }

        // 检查JavaScript上下文
        if (this.checkJavaScriptContext(element)) {
            types.push('javascript');
        }

        // 检查CSS上下文
        if (this.checkCSSContext(element)) {
            types.push('css');
        }

        return types;
    }

    // 检查HTML上下文
    checkHTMLContext(element) {
        const htmlContext = this.contexts.html;
        
        // 检查标签名
        if (htmlContext.attributes.includes(element.tagName?.toLowerCase())) {
            return true;
        }

        // 检查属性
        for (const attr of htmlContext.attributes) {
            if (element.hasAttribute(attr)) {
                return true;
            }
        }

        // 检查内容模式
        const content = element.innerHTML || element.textContent;
        for (const pattern of htmlContext.patterns) {
            if (pattern.test(content)) {
                return true;
            }
        }

        return false;
    }

    // 检查JavaScript上下文
    checkJavaScriptContext(element) {
        const jsContext = this.contexts.javascript;
        
        // 检查脚本标签
        if (element.tagName?.toLowerCase() === 'script') {
            return true;
        }

        // 检查事件处理器
        for (const attr of jsContext.attributes) {
            if (element.hasAttribute(attr)) {
                return true;
            }
        }

        // 检查内容模式
        const content = element.innerHTML || element.textContent;
        for (const pattern of jsContext.patterns) {
            if (pattern.test(content)) {
                return true;
            }
        }

        return false;
    }

    // 检查CSS上下文
    checkCSSContext(element) {
        const cssContext = this.contexts.css;
        
        // 检查样式标签
        if (element.tagName?.toLowerCase() === 'style') {
            return true;
        }

        // 检查样式属性
        if (element.hasAttribute('style')) {
            return true;
        }

        // 检查内容模式
        const content = element.innerHTML || element.textContent;
        for (const pattern of cssContext.patterns) {
            if (pattern.test(content)) {
                return true;
            }
        }

        return false;
    }

    // 分析位置
    analyzeLocation(element) {
        const location = {
            tagName: element.tagName?.toLowerCase(),
            attributeName: null,
            parentTag: null,
            domPath: this.generateDOMPath(element),
            id: element.id,
            class: element.className
        };

        // 获取属性名
        for (const attr of element.attributes) {
            if (this.isInjectableAttribute(attr.name)) {
                location.attributeName = attr.name;
                break;
            }
        }

        // 获取父标签
        if (element.parentElement) {
            location.parentTag = element.parentElement.tagName?.toLowerCase();
        }

        return location;
    }

    // 生成DOM路径
    generateDOMPath(element) {
        const path = [];
        let current = element;

        while (current && current.tagName) {
            let selector = current.tagName.toLowerCase();
            
            // 添加ID选择器
            if (current.id) {
                selector += `#${current.id}`;
            }
            
            // 添加类选择器
            if (current.className) {
                selector += `.${current.className.split(' ').join('.')}`;
            }

            path.unshift(selector);
            current = current.parentElement;
        }

        return path.join(' > ');
    }

    // 检查可注入属性
    isInjectableAttribute(attrName) {
        const injectableAttrs = [
            'href', 'src', 'onerror', 'onload', 'onclick',
            'onmouseover', 'onmouseout', 'onkeypress',
            'onkeydown', 'onkeyup', 'onfocus', 'onblur',
            'style', 'data-*'
        ];

        return injectableAttrs.some(attr => 
            attrName.toLowerCase() === attr || 
            attrName.toLowerCase().startsWith('data-')
        );
    }

    // 检测净化方法
    detectSanitization(element) {
        const sanitization = {
            detected: false,
            methods: [],
            effectiveness: null
        };

        // 检查HTML净化
        const htmlSanitization = this.checkHTMLSanitization(element);
        if (htmlSanitization.detected) {
            sanitization.detected = true;
            sanitization.methods.push(...htmlSanitization.methods);
        }

        // 检查JavaScript净化
        const jsSanitization = this.checkJavaScriptSanitization(element);
        if (jsSanitization.detected) {
            sanitization.detected = true;
            sanitization.methods.push(...jsSanitization.methods);
        }

        // 检查CSS净化
        const cssSanitization = this.checkCSSSanitization(element);
        if (cssSanitization.detected) {
            sanitization.detected = true;
            sanitization.methods.push(...cssSanitization.methods);
        }

        // 评估净化效果
        if (sanitization.detected) {
            sanitization.effectiveness = this.evaluateSanitizationEffectiveness(
                element,
                sanitization.methods
            );
        }

        return sanitization;
    }

    // 检查HTML净化
    checkHTMLSanitization(element) {
        const result = {
            detected: false,
            methods: []
        };

        const htmlSanitization = this.sanitizationMethods.html;
        const content = element.innerHTML || element.textContent;

        // 检查模式
        for (const pattern of htmlSanitization.patterns) {
            if (pattern.test(content)) {
                result.detected = true;
                result.methods.push(pattern.toString());
            }
        }

        // 检查函数
        for (const func of htmlSanitization.functions) {
            if (content.includes(func)) {
                result.detected = true;
                result.methods.push(func);
            }
        }

        return result;
    }

    // 检查JavaScript净化
    checkJavaScriptSanitization(element) {
        const result = {
            detected: false,
            methods: []
        };

        const jsSanitization = this.sanitizationMethods.javascript;
        const content = element.innerHTML || element.textContent;

        // 检查模式
        for (const pattern of jsSanitization.patterns) {
            if (pattern.test(content)) {
                result.detected = true;
                result.methods.push(pattern.toString());
            }
        }

        // 检查函数
        for (const func of jsSanitization.functions) {
            if (content.includes(func)) {
                result.detected = true;
                result.methods.push(func);
            }
        }

        return result;
    }

    // 检查CSS净化
    checkCSSSanitization(element) {
        const result = {
            detected: false,
            methods: []
        };

        const cssSanitization = this.sanitizationMethods.css;
        const content = element.innerHTML || element.textContent;

        // 检查模式
        for (const pattern of cssSanitization.patterns) {
            if (pattern.test(content)) {
                result.detected = true;
                result.methods.push(pattern.toString());
            }
        }

        // 检查函数
        for (const func of cssSanitization.functions) {
            if (content.includes(func)) {
                result.detected = true;
                result.methods.push(func);
            }
        }

        return result;
    }

    // 评估净化效果
    evaluateSanitizationEffectiveness(element, methods) {
        const effectiveness = {
            level: 'unknown',
            details: []
        };

        // 检查HTML转义
        if (methods.some(m => m.includes('htmlspecialchars') || m.includes('htmlentities'))) {
            effectiveness.level = 'high';
            effectiveness.details.push('HTML special characters are properly escaped');
        }

        // 检查标签剥离
        if (methods.some(m => m.includes('strip_tags'))) {
            effectiveness.level = 'high';
            effectiveness.details.push('HTML tags are stripped');
        }

        // 检查JavaScript转义
        if (methods.some(m => m.includes('escape') || m.includes('encodeURI'))) {
            effectiveness.level = 'high';
            effectiveness.details.push('JavaScript special characters are properly escaped');
        }

        // 检查CSS转义
        if (methods.some(m => m.includes('sanitizeCSS'))) {
            effectiveness.level = 'high';
            effectiveness.details.push('CSS special characters are properly escaped');
        }

        return effectiveness;
    }

    // 分析编码
    analyzeEncoding(element) {
        const encoding = {
            charset: null,
            contentEncoding: null,
            responseEncoding: null
        };

        // 检测字符集
        const charset = this.detectCharset(element);
        if (charset) {
            encoding.charset = charset;
        }

        // 检测内容编码
        const contentEncoding = this.detectContentEncoding(element);
        if (contentEncoding) {
            encoding.contentEncoding = contentEncoding;
        }

        // 检测响应编码
        const responseEncoding = this.detectResponseEncoding(element);
        if (responseEncoding) {
            encoding.responseEncoding = responseEncoding;
        }

        return encoding;
    }

    // 检测字符集
    detectCharset(element) {
        // 检查meta标签
        const metaCharset = document.querySelector('meta[charset]');
        if (metaCharset) {
            return metaCharset.getAttribute('charset');
        }

        // 检查Content-Type头
        const contentType = document.querySelector('meta[http-equiv="Content-Type"]');
        if (contentType) {
            const content = contentType.getAttribute('content');
            const match = content.match(/charset=([^;]+)/i);
            if (match) {
                return match[1];
            }
        }

        return null;
    }

    // 检测内容编码
    detectContentEncoding(element) {
        const content = element.innerHTML || element.textContent;

        // 检查Base64编码
        if (/^[A-Za-z0-9+/=]+$/.test(content)) {
            return 'base64';
        }

        // 检查URL编码
        if (/%[0-9A-Fa-f]{2}/.test(content)) {
            return 'url';
        }

        // 检查HTML编码
        if (/&[a-zA-Z]+;/.test(content)) {
            return 'html';
        }

        // 检查JavaScript编码
        if (/\\[xX][0-9A-Fa-f]{2}/.test(content)) {
            return 'javascript';
        }

        return null;
    }

    // 检测响应编码
    detectResponseEncoding(element) {
        // 这里需要实现检测响应编码的逻辑
        // 由于浏览器安全限制，可能需要通过其他方式获取
        return null;
    }

    // 分析父上下文
    analyzeParentContext(element) {
        const parentContext = {
            type: null,
            sanitization: null,
            encoding: null
        };

        if (element.parentElement) {
            // 检测父元素上下文类型
            parentContext.type = this.detectContextType(element.parentElement);

            // 检测父元素净化方法
            parentContext.sanitization = this.detectSanitization(element.parentElement);

            // 检测父元素编码
            parentContext.encoding = this.analyzeEncoding(element.parentElement);
        }

        return parentContext;
    }

    // 生成建议
    generateRecommendations(analysis) {
        const recommendations = [];

        // 基于上下文类型的建议
        for (const type of analysis.type) {
            recommendations.push({
                type: 'context',
                description: `Use appropriate payload for ${type} context`,
                priority: 'high'
            });
        }

        // 基于位置的建议
        if (analysis.location.attributeName) {
            recommendations.push({
                type: 'location',
                description: `Consider attribute-specific payload for ${analysis.location.attributeName}`,
                priority: 'medium'
            });
        }

        // 基于净化方法的建议
        if (analysis.sanitization.detected) {
            recommendations.push({
                type: 'sanitization',
                description: `Bypass detected sanitization methods: ${analysis.sanitization.methods.join(', ')}`,
                priority: 'high'
            });
        }

        // 基于编码的建议
        if (analysis.encoding.charset || analysis.encoding.contentEncoding) {
            recommendations.push({
                type: 'encoding',
                description: `Consider encoding-specific payload for detected encodings`,
                priority: 'medium'
            });
        }

        // 基于父上下文的建议
        if (analysis.parentContext.type) {
            recommendations.push({
                type: 'parent',
                description: `Consider parent context restrictions: ${analysis.parentContext.type.join(', ')}`,
                priority: 'medium'
            });
        }

        return recommendations;
    }
}

export const contextAnalyzer = new ContextAnalyzer(); 