class EnvironmentAwareDetector {
    constructor() {
        this.frameworks = {
            react: {
                patterns: [
                    /React\.version/,
                    /__REACT_DEVTOOLS_GLOBAL_HOOK__/,
                    /ReactDOM/,
                    /createElement/,
                    /useState/,
                    /useEffect/
                ],
                features: ['JSX', 'Hooks', 'Virtual DOM']
            },
            angular: {
                patterns: [
                    /ng\.version/,
                    /angular\.version/,
                    /ng-app/,
                    /ng-controller/,
                    /ng-model/
                ],
                features: ['Two-way binding', 'Dependency injection', 'Directives']
            },
            vue: {
                patterns: [
                    /Vue\.version/,
                    /vue\.version/,
                    /v-model/,
                    /v-for/,
                    /v-if/
                ],
                features: ['Reactive data', 'Component system', 'Virtual DOM']
            },
            jquery: {
                patterns: [
                    /jQuery\.fn\.jquery/,
                    /\$\.fn\.jquery/,
                    /\$\.ajax/,
                    /\$\.get/,
                    /\$\.post/
                ],
                features: ['AJAX', 'DOM manipulation', 'Event handling']
            }
        };

        this.securityMechanisms = {
            csp: {
                headers: ['Content-Security-Policy', 'X-Content-Security-Policy'],
                patterns: [
                    /script-src/,
                    /style-src/,
                    /img-src/,
                    /connect-src/,
                    /frame-src/
                ]
            },
            xssProtection: {
                headers: ['X-XSS-Protection'],
                patterns: [/1; mode=block/]
            },
            csrfProtection: {
                headers: ['X-CSRF-Token', 'XSRF-TOKEN'],
                patterns: [/csrf/]
            },
            waf: {
                headers: ['X-WAF', 'X-Firewall'],
                patterns: [
                    /mod_security/,
                    /cloudflare/,
                    /aws/,
                    /akamai/
                ]
            }
        };

        this.browsers = {
            chrome: {
                patterns: [/Chrome/],
                features: ['Shadow DOM', 'Web Components']
            },
            firefox: {
                patterns: [/Firefox/],
                features: ['XUL', 'Gecko']
            },
            safari: {
                patterns: [/Safari/],
                features: ['WebKit', 'Safari Extensions']
            },
            edge: {
                patterns: [/Edge/],
                features: ['Chromium', 'Edge Extensions']
            }
        };

        this.encoding = {
            charset: {
                headers: ['Content-Type'],
                patterns: [
                    /charset=utf-8/,
                    /charset=iso-8859-1/,
                    /charset=ascii/
                ]
            },
            contentEncoding: {
                headers: ['Content-Encoding'],
                patterns: [
                    /gzip/,
                    /deflate/,
                    /br/
                ]
            },
            responseEncoding: {
                headers: ['Transfer-Encoding'],
                patterns: [
                    /chunked/,
                    /identity/
                ]
            }
        };

        this.sanitization = {
            libraries: {
                patterns: [
                    /DOMPurify/,
                    /sanitize-html/,
                    /xss/,
                    /escape-html/
                ]
            },
            methods: {
                patterns: [
                    /escape/,
                    /sanitize/,
                    /encode/,
                    /filter/
                ]
            }
        };
    }

    // 检测框架
    detectFrameworks() {
        const results = {
            detected: [],
            versions: {},
            features: {}
        };

        for (const [name, framework] of Object.entries(this.frameworks)) {
            // 检查全局对象
            if (window[name] || window[name.charAt(0).toUpperCase() + name.slice(1)]) {
                results.detected.push(name);
                results.versions[name] = this.getFrameworkVersion(name);
                results.features[name] = this.detectFrameworkFeatures(name);
            }

            // 检查DOM特征
            for (const pattern of framework.patterns) {
                if (pattern.test(document.documentElement.innerHTML)) {
                    if (!results.detected.includes(name)) {
                        results.detected.push(name);
                        results.versions[name] = this.getFrameworkVersion(name);
                        results.features[name] = this.detectFrameworkFeatures(name);
                    }
                }
            }
        }

        return results;
    }

    // 获取框架版本
    getFrameworkVersion(framework) {
        try {
            switch (framework) {
                case 'react':
                    return window.React?.version || 'unknown';
                case 'angular':
                    return window.angular?.version?.full || 'unknown';
                case 'vue':
                    return window.Vue?.version || 'unknown';
                case 'jquery':
                    return window.jQuery?.fn?.jquery || 'unknown';
                default:
                    return 'unknown';
            }
        } catch (error) {
            return 'unknown';
        }
    }

    // 检测框架特性
    detectFrameworkFeatures(framework) {
        const features = [];
        const frameworkFeatures = this.frameworks[framework]?.features || [];

        for (const feature of frameworkFeatures) {
            if (this.checkFeatureSupport(feature)) {
                features.push(feature);
            }
        }

        return features;
    }

    // 检查特性支持
    checkFeatureSupport(feature) {
        switch (feature) {
            case 'JSX':
                return typeof Babel !== 'undefined';
            case 'Hooks':
                return typeof React?.useState === 'function';
            case 'Virtual DOM':
                return typeof document.createDocumentFragment === 'function';
            case 'Two-way binding':
                return typeof angular !== 'undefined' && typeof angular.module === 'function';
            case 'Dependency injection':
                return typeof angular !== 'undefined' && typeof angular.injector === 'function';
            case 'Directives':
                return typeof angular !== 'undefined' && typeof angular.directive === 'function';
            case 'Reactive data':
                return typeof Vue !== 'undefined' && typeof Vue.observable === 'function';
            case 'Component system':
                return typeof Vue !== 'undefined' && typeof Vue.component === 'function';
            case 'AJAX':
                return typeof jQuery !== 'undefined' && typeof jQuery.ajax === 'function';
            case 'DOM manipulation':
                return typeof jQuery !== 'undefined' && typeof jQuery.fn.html === 'function';
            case 'Event handling':
                return typeof jQuery !== 'undefined' && typeof jQuery.fn.on === 'function';
            default:
                return false;
        }
    }

    // 检测安全机制
    detectSecurityMechanisms() {
        const results = {
            csp: this.detectCSP(),
            xssProtection: this.detectXSSProtection(),
            csrfProtection: this.detectCSRFProtection(),
            waf: this.detectWAF()
        };

        return results;
    }

    // 检测CSP
    detectCSP() {
        const csp = {
            enabled: false,
            directives: {},
            reportOnly: false
        };

        const headers = this.getResponseHeaders();
        for (const header of this.securityMechanisms.csp.headers) {
            const value = headers.get(header);
            if (value) {
                csp.enabled = true;
                if (header.includes('Report-Only')) {
                    csp.reportOnly = true;
                }
                csp.directives = this.parseCSPDirectives(value);
            }
        }

        return csp;
    }

    // 解析CSP指令
    parseCSPDirectives(cspString) {
        const directives = {};
        const parts = cspString.split(';');

        for (const part of parts) {
            const [name, ...values] = part.trim().split(' ');
            if (name && values.length > 0) {
                directives[name] = values;
            }
        }

        return directives;
    }

    // 检测XSS保护
    detectXSSProtection() {
        const headers = this.getResponseHeaders();
        for (const header of this.securityMechanisms.xssProtection.headers) {
            const value = headers.get(header);
            if (value) {
                return {
                    enabled: true,
                    mode: value.includes('mode=block') ? 'block' : 'filter'
                };
            }
        }
        return { enabled: false };
    }

    // 检测CSRF保护
    detectCSRFProtection() {
        const headers = this.getResponseHeaders();
        for (const header of this.securityMechanisms.csrfProtection.headers) {
            const value = headers.get(header);
            if (value) {
                return {
                    enabled: true,
                    token: value
                };
            }
        }
        return { enabled: false };
    }

    // 检测WAF
    detectWAF() {
        const headers = this.getResponseHeaders();
        for (const header of this.securityMechanisms.waf.headers) {
            const value = headers.get(header);
            if (value) {
                for (const pattern of this.securityMechanisms.waf.patterns) {
                    if (pattern.test(value)) {
                        return {
                            enabled: true,
                            type: pattern.toString().match(/\/(\w+)\//)[1]
                        };
                    }
                }
            }
        }
        return { enabled: false };
    }

    // 检测浏览器
    detectBrowser() {
        const results = {
            name: 'unknown',
            version: 'unknown',
            features: []
        };

        const userAgent = navigator.userAgent;
        for (const [name, browser] of Object.entries(this.browsers)) {
            for (const pattern of browser.patterns) {
                if (pattern.test(userAgent)) {
                    results.name = name;
                    results.version = this.getBrowserVersion(userAgent, name);
                    results.features = this.detectBrowserFeatures(name);
                    return results;
                }
            }
        }

        return results;
    }

    // 获取浏览器版本
    getBrowserVersion(userAgent, browser) {
        const versionMatch = userAgent.match(new RegExp(`${browser}\\/([\\d.]+)`));
        return versionMatch ? versionMatch[1] : 'unknown';
    }

    // 检测浏览器特性
    detectBrowserFeatures(browser) {
        const features = [];
        const browserFeatures = this.browsers[browser]?.features || [];

        for (const feature of browserFeatures) {
            if (this.checkBrowserFeatureSupport(feature)) {
                features.push(feature);
            }
        }

        return features;
    }

    // 检查浏览器特性支持
    checkBrowserFeatureSupport(feature) {
        switch (feature) {
            case 'Shadow DOM':
                return typeof Element.prototype.attachShadow === 'function';
            case 'Web Components':
                return typeof customElements !== 'undefined';
            case 'XUL':
                return typeof XULDocument !== 'undefined';
            case 'Gecko':
                return typeof InstallTrigger !== 'undefined';
            case 'WebKit':
                return typeof WebKitCSSMatrix !== 'undefined';
            case 'Safari Extensions':
                return typeof safari !== 'undefined';
            case 'Chromium':
                return typeof chrome !== 'undefined';
            case 'Edge Extensions':
                return typeof browser !== 'undefined';
            default:
                return false;
        }
    }

    // 检测编码
    detectEncoding() {
        const results = {
            charset: this.detectCharset(),
            contentEncoding: this.detectContentEncoding(),
            responseEncoding: this.detectResponseEncoding()
        };

        return results;
    }

    // 检测字符集
    detectCharset() {
        const headers = this.getResponseHeaders();
        for (const header of this.encoding.charset.headers) {
            const value = headers.get(header);
            if (value) {
                for (const pattern of this.encoding.charset.patterns) {
                    if (pattern.test(value)) {
                        return {
                            detected: true,
                            charset: pattern.toString().match(/charset=(\w+)/)[1]
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    // 检测内容编码
    detectContentEncoding() {
        const headers = this.getResponseHeaders();
        for (const header of this.encoding.contentEncoding.headers) {
            const value = headers.get(header);
            if (value) {
                for (const pattern of this.encoding.contentEncoding.patterns) {
                    if (pattern.test(value)) {
                        return {
                            detected: true,
                            encoding: pattern.toString().match(/\/(\w+)/)[1]
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    // 检测响应编码
    detectResponseEncoding() {
        const headers = this.getResponseHeaders();
        for (const header of this.encoding.responseEncoding.headers) {
            const value = headers.get(header);
            if (value) {
                for (const pattern of this.encoding.responseEncoding.patterns) {
                    if (pattern.test(value)) {
                        return {
                            detected: true,
                            encoding: pattern.toString().match(/\/(\w+)/)[1]
                        };
                    }
                }
            }
        }
        return { detected: false };
    }

    // 检测净化方法
    detectSanitization() {
        const results = {
            libraries: this.detectSanitizationLibraries(),
            methods: this.detectSanitizationMethods()
        };

        return results;
    }

    // 检测净化库
    detectSanitizationLibraries() {
        const libraries = [];
        const scripts = document.getElementsByTagName('script');

        for (const script of scripts) {
            const src = script.src || '';
            for (const pattern of this.sanitization.libraries.patterns) {
                if (pattern.test(src)) {
                    libraries.push(pattern.toString().match(/\/(\w+)/)[1]);
                }
            }
        }

        return libraries;
    }

    // 检测净化方法
    detectSanitizationMethods() {
        const methods = [];
        const scripts = document.getElementsByTagName('script');

        for (const script of scripts) {
            const content = script.textContent || '';
            for (const pattern of this.sanitization.methods.patterns) {
                if (pattern.test(content)) {
                    methods.push(pattern.toString().match(/\/(\w+)/)[1]);
                }
            }
        }

        return methods;
    }

    // 获取响应头
    getResponseHeaders() {
        // 这里需要实现获取响应头的逻辑
        // 由于浏览器安全限制，可能需要通过其他方式获取
        return new Headers();
    }

    // 生成环境分析报告
    generateEnvironmentReport() {
        const report = {
            timestamp: new Date().toISOString(),
            frameworks: this.detectFrameworks(),
            security: this.detectSecurityMechanisms(),
            browser: this.detectBrowser(),
            encoding: this.detectEncoding(),
            sanitization: this.detectSanitization(),
            recommendations: this.generateRecommendations()
        };

        return report;
    }

    // 生成建议
    generateRecommendations() {
        const recommendations = [];
        const environment = this.generateEnvironmentReport();

        // 基于框架的建议
        if (environment.frameworks.detected.length > 0) {
            recommendations.push({
                type: 'framework',
                description: `Detected frameworks: ${environment.frameworks.detected.join(', ')}`,
                priority: 'medium'
            });
        }

        // 基于安全机制的建议
        if (environment.security.csp.enabled) {
            recommendations.push({
                type: 'security',
                description: 'CSP is enabled - adjust payloads accordingly',
                priority: 'high'
            });
        }

        if (environment.security.waf.enabled) {
            recommendations.push({
                type: 'security',
                description: `WAF detected (${environment.security.waf.type}) - use appropriate bypass techniques`,
                priority: 'high'
            });
        }

        // 基于编码的建议
        if (environment.encoding.charset.detected) {
            recommendations.push({
                type: 'encoding',
                description: `Character set detected: ${environment.encoding.charset.charset}`,
                priority: 'medium'
            });
        }

        // 基于净化方法的建议
        if (environment.sanitization.libraries.length > 0) {
            recommendations.push({
                type: 'sanitization',
                description: `Sanitization libraries detected: ${environment.sanitization.libraries.join(', ')}`,
                priority: 'high'
            });
        }

        return recommendations;
    }
}

export const environmentAwareDetector = new EnvironmentAwareDetector(); 