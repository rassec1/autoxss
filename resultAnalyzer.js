class XSSResultAnalyzer {
    constructor() {
        this.xssPatterns = {
            reflected: /<script[^>]*>.*?<\/script>/i,
            dom: /document\.write|innerHTML|outerHTML|insertAdjacentHTML/i,
            event: /on\w+\s*=/i,
            data: /data:\s*text\/html/i
        };

        this.confidenceFactors = {
            reflected: 0.8,
            dom: 0.7,
            event: 0.6,
            data: 0.5
        };
    }

    analyzeResponse(results, input) {
        const analysis = {
            confidence: 0,
            type: null,
            details: {},
            evidence: []
        };

        // 分析每个测试结果
        for (const result of results) {
            if (result.success) {
                const resultAnalysis = this.analyzeSingleResult(result);
                analysis.evidence.push(resultAnalysis);
                
                // 更新总体置信度
                analysis.confidence = Math.max(analysis.confidence, resultAnalysis.confidence);
                
                // 确定漏洞类型
                if (!analysis.type || resultAnalysis.confidence > analysis.confidence) {
                    analysis.type = resultAnalysis.type;
                }
            }
        }

        // 添加详细信息
        analysis.details = {
            input: input,
            evidence: analysis.evidence,
            timestamp: new Date().toISOString()
        };

        return analysis;
    }

    analyzeSingleResult(result) {
        const analysis = {
            type: null,
            confidence: 0,
            patterns: [],
            context: result.context
        };

        // 检查反射型XSS
        if (this.xssPatterns.reflected.test(result.response)) {
            analysis.type = 'reflected';
            analysis.confidence = this.confidenceFactors.reflected;
            analysis.patterns.push('reflected');
        }

        // 检查DOM型XSS
        if (this.xssPatterns.dom.test(result.response)) {
            analysis.type = 'dom';
            analysis.confidence = this.confidenceFactors.dom;
            analysis.patterns.push('dom');
        }

        // 检查事件处理器XSS
        if (this.xssPatterns.event.test(result.response)) {
            analysis.type = 'event';
            analysis.confidence = this.confidenceFactors.event;
            analysis.patterns.push('event');
        }

        // 检查数据URI XSS
        if (this.xssPatterns.data.test(result.response)) {
            analysis.type = 'data';
            analysis.confidence = this.confidenceFactors.data;
            analysis.patterns.push('data');
        }

        // 分析上下文
        if (result.context) {
            analysis.context = this.analyzeContext(result.context);
        }

        return analysis;
    }

    analyzeContext(context) {
        const analysis = {
            type: context.type,
            location: context.location,
            encoding: context.encoding,
            sanitization: this.detectSanitization(context)
        };

        return analysis;
    }

    detectSanitization(context) {
        const sanitization = {
            detected: false,
            method: null,
            effectiveness: 0
        };

        // 检查常见的净化方法
        const sanitizationPatterns = {
            htmlEscape: /&[a-zA-Z]+;/g,
            jsEscape: /\\[^a-zA-Z]/g,
            urlEncode: /%[0-9A-Fa-f]{2}/g
        };

        for (const [method, pattern] of Object.entries(sanitizationPatterns)) {
            if (pattern.test(context.value)) {
                sanitization.detected = true;
                sanitization.method = method;
                sanitization.effectiveness = this.calculateSanitizationEffectiveness(context, method);
                break;
            }
        }

        return sanitization;
    }

    calculateSanitizationEffectiveness(context, method) {
        let effectiveness = 0;

        switch (method) {
            case 'htmlEscape':
                effectiveness = this.calculateHtmlEscapeEffectiveness(context);
                break;
            case 'jsEscape':
                effectiveness = this.calculateJsEscapeEffectiveness(context);
                break;
            case 'urlEncode':
                effectiveness = this.calculateUrlEncodeEffectiveness(context);
                break;
        }

        return effectiveness;
    }

    calculateHtmlEscapeEffectiveness(context) {
        // 计算HTML转义的有效性
        const escapedChars = (context.value.match(/&[a-zA-Z]+;/g) || []).length;
        const totalChars = context.value.length;
        return escapedChars / totalChars;
    }

    calculateJsEscapeEffectiveness(context) {
        // 计算JavaScript转义的有效性
        const escapedChars = (context.value.match(/\\[^a-zA-Z]/g) || []).length;
        const totalChars = context.value.length;
        return escapedChars / totalChars;
    }

    calculateUrlEncodeEffectiveness(context) {
        // 计算URL编码的有效性
        const encodedChars = (context.value.match(/%[0-9A-Fa-f]{2}/g) || []).length;
        const totalChars = context.value.length;
        return encodedChars / totalChars;
    }

    generateReport(analysis) {
        return {
            summary: {
                isVulnerable: analysis.confidence > 0.8,
                confidence: analysis.confidence,
                type: analysis.type
            },
            details: {
                input: analysis.details.input,
                evidence: analysis.evidence,
                timestamp: analysis.details.timestamp
            },
            recommendations: this.generateRecommendations(analysis)
        };
    }

    generateRecommendations(analysis) {
        const recommendations = [];

        if (analysis.confidence > 0.8) {
            recommendations.push({
                type: 'critical',
                message: '发现高危XSS漏洞，建议立即修复',
                action: '实施输入验证和输出编码'
            });
        } else if (analysis.confidence > 0.5) {
            recommendations.push({
                type: 'warning',
                message: '发现潜在的XSS漏洞，建议进行安全审查',
                action: '加强输入验证和输出编码'
            });
        }

        // 根据漏洞类型添加具体建议
        if (analysis.type === 'reflected') {
            recommendations.push({
                type: 'info',
                message: '建议实施CSP策略',
                action: '配置Content-Security-Policy头'
            });
        } else if (analysis.type === 'dom') {
            recommendations.push({
                type: 'info',
                message: '建议使用安全的DOM操作方法',
                action: '使用textContent替代innerHTML'
            });
        }

        return recommendations;
    }
}

export const resultAnalyzer = new XSSResultAnalyzer(); 