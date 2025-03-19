class EnvironmentDetector {
    constructor() {
        this.serverSignatures = {
            apache: ['Apache', 'X-Powered-By: Apache'],
            nginx: ['nginx', 'X-Powered-By: nginx'],
            iis: ['IIS', 'X-Powered-By: ASP.NET'],
            tomcat: ['Tomcat', 'X-Powered-By: JSP'],
            jetty: ['Jetty', 'X-Powered-By: Jetty']
        };

        this.frameworkSignatures = {
            vue: ['__VUE__', 'vue'],
            react: ['__REACT_DEVTOOLS_GLOBAL_HOOK__', 'react'],
            angular: ['angular', 'ng-'],
            svelte: ['__svelte'],
            jquery: ['jQuery', '$'],
            bootstrap: ['bootstrap'],
            materialize: ['Materialize']
        };

        this.securityHeaders = [
            'X-XSS-Protection',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ];
    }

    detectEnvironment() {
        return {
            server: this.detectServer(),
            framework: this.detectFramework(),
            security: this.detectSecurity(),
            encoding: this.detectEncoding()
        };
    }

    detectServer() {
        const headers = this.getResponseHeaders();
        const server = headers.get('server') || '';
        
        for (const [name, signatures] of Object.entries(this.serverSignatures)) {
            if (signatures.some(sig => server.includes(sig))) {
                return name;
            }
        }
        
        return 'unknown';
    }

    detectFramework() {
        const frameworks = [];
        
        // 检查全局对象
        for (const [name, signatures] of Object.entries(this.frameworkSignatures)) {
            if (signatures.some(sig => window[sig] || document.querySelector(`[${sig}]`))) {
                frameworks.push(name);
            }
        }
        
        // 检查DOM特征
        if (document.querySelector('[ng-app]')) frameworks.push('angular');
        if (document.querySelector('[v-app]')) frameworks.push('vue');
        if (document.querySelector('[data-reactroot]')) frameworks.push('react');
        
        return frameworks;
    }

    detectSecurity() {
        const headers = this.getResponseHeaders();
        const security = {
            headers: {},
            waf: this.detectWAF(),
            csp: this.detectCSP()
        };
        
        // 检查安全头
        for (const header of this.securityHeaders) {
            security.headers[header] = headers.get(header) || null;
        }
        
        return security;
    }

    detectEncoding() {
        const headers = this.getResponseHeaders();
        const contentType = headers.get('content-type') || '';
        const charset = contentType.match(/charset=([^;]+)/i);
        
        return {
            charset: charset ? charset[1] : 'utf-8',
            contentEncoding: headers.get('content-encoding') || 'none'
        };
    }

    detectWAF() {
        const headers = this.getResponseHeaders();
        const wafSignatures = {
            modSecurity: ['ModSecurity', 'NOYB'],
            cloudflare: ['Cloudflare', 'cf-ray'],
            aws: ['AWS WAF', 'x-amzn-RequestId'],
            akamai: ['Akamai', 'AkamaiGHost']
        };
        
        for (const [name, signatures] of Object.entries(wafSignatures)) {
            if (signatures.some(sig => headers.get('server')?.includes(sig))) {
                return name;
            }
        }
        
        return 'unknown';
    }

    detectCSP() {
        const headers = this.getResponseHeaders();
        const csp = headers.get('content-security-policy');
        
        if (!csp) return null;
        
        return {
            enabled: true,
            directives: this.parseCSPDirectives(csp)
        };
    }

    parseCSPDirectives(csp) {
        const directives = {};
        const parts = csp.split(';');
        
        for (const part of parts) {
            const [directive, ...values] = part.trim().split(' ');
            if (directive && values.length) {
                directives[directive] = values;
            }
        }
        
        return directives;
    }

    getResponseHeaders() {
        // 这里应该实现获取响应头的逻辑
        // 可以通过XMLHttpRequest或fetch API获取
        return new Headers();
    }

    adjustStrategy(environment) {
        const strategies = {
            apache: this.apacheStrategy(),
            nginx: this.nginxStrategy(),
            iis: this.iisStrategy(),
            unknown: this.defaultStrategy()
        };
        
        return strategies[environment.server] || strategies.unknown;
    }

    apacheStrategy() {
        return {
            filterPayloads: (payloads, env) => {
                // Apache特定的payload过滤逻辑
                return payloads.filter(payload => 
                    !payload.includes('..') && // 避免目录遍历
                    !payload.includes('<!--')  // 避免注释注入
                );
            }
        };
    }

    nginxStrategy() {
        return {
            filterPayloads: (payloads, env) => {
                // Nginx特定的payload过滤逻辑
                return payloads.filter(payload => 
                    !payload.includes('$') && // 避免变量注入
                    !payload.includes('\\')   // 避免路径注入
                );
            }
        };
    }

    iisStrategy() {
        return {
            filterPayloads: (payloads, env) => {
                // IIS特定的payload过滤逻辑
                return payloads.filter(payload => 
                    !payload.includes('..') && // 避免目录遍历
                    !payload.includes('\\')    // 避免路径注入
                );
            }
        };
    }

    defaultStrategy() {
        return {
            filterPayloads: (payloads, env) => payloads
        };
    }
}

export const environmentDetector = new EnvironmentDetector(); 