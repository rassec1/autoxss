// 默认配置
const defaultConfig = {
    whitelist: {
        enabled: true,
        domains: ['baidu.com', '360.cn', 'google.com', 'github.com', 'microsoft.com'],
        includeSubdomains: true
    },
    scanTargets: {
        enabled: false,
        targets: [
            {
                domain: 'example.com',
                includeSubdomains: true,
                paths: ['/'],
                excludePaths: ['/admin', '/private'],
                methods: ['GET', 'POST'],
                parameters: {
                    include: ['*'],
                    exclude: ['token', 'session']
                }
            }
        ],
        depth: {
            maxDepth: 3,
            followLinks: true,
            excludePatterns: ['/logout', '/login']
        }
    },
    scan: {
        scanParameters: true,
        scanForms: true,
        scanHiddenInputs: true,
        scanPseudoStatic: true
    },
    report: {
        showAlerts: true,
        consoleOutput: true,
        markVulnerableElements: true
    }
};

// 配置验证器
const ConfigValidator = {
    validate(config) {
        const errors = [];
        
        // 验证白名单配置
        if (!Array.isArray(config.whitelist.domains)) {
            errors.push('whitelist.domains must be an array');
        }
        
        // 验证扫描目标配置
        if (config.scanTargets.enabled) {
            if (!Array.isArray(config.scanTargets.targets)) {
                errors.push('scanTargets.targets must be an array');
            } else {
                config.scanTargets.targets.forEach((target, index) => {
                    if (!target.domain) {
                        errors.push(`Target ${index} must have a domain`);
                    }
                    if (!Array.isArray(target.paths)) {
                        errors.push(`Target ${index} paths must be an array`);
                    }
                    if (!Array.isArray(target.excludePaths)) {
                        errors.push(`Target ${index} excludePaths must be an array`);
                    }
                });
            }
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }
};

// 配置管理器类
class ConfigManager {
    constructor() {
        this.config = null;
    }

    async load() {
        try {
            const result = await chrome.storage.local.get('config');
            this.config = result.config || defaultConfig;
            return this.config;
        } catch (error) {
            console.error('Error loading config:', error);
            this.config = defaultConfig;
            return this.config;
        }
    }

    async save(config) {
        try {
            await chrome.storage.local.set({ config });
            this.config = config;
            return true;
        } catch (error) {
            console.error('Error saving config:', error);
            return false;
        }
    }

    get() {
        return this.config || defaultConfig;
    }
}

// 导出配置和配置管理器
export default defaultConfig;
export { ConfigValidator, ConfigManager }; 