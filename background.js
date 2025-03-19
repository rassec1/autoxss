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

// 跟踪已准备好的标签页
const readyTabs = new Set();

// 检查并开始扫描
async function checkAndStartScan(tabId, url) {
    try {
        // 检查是否是扫描目标
        const configManager = new ConfigManager();
        const config = await configManager.load();
        
        if (config && config.scanTargets.enabled) {
            const domain = new URL(url).hostname;
            const isTarget = config.scanTargets.targets.some(target => {
                if (target.includeSubdomains) {
                    return domain.endsWith(target.domain);
                }
                return domain === target.domain;
            });
            
            if (isTarget) {
                // 向content script发送开始扫描的消息
                chrome.tabs.sendMessage(tabId, { type: 'START_SCAN' });
            }
        }
    } catch (error) {
        console.error('Error checking scan target:', error);
    }
}

// 监听标签页更新
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // 检查是否已注入content script
        if (readyTabs.has(tabId)) {
            checkAndStartScan(tabId, tab.url);
        }
    }
});

// 监听来自content script的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'CONTENT_SCRIPT_READY') {
        // 记录标签页已就绪
        if (sender.tab && sender.tab.id) {
            readyTabs.add(sender.tab.id);
            // 立即检查并开始扫描
            checkAndStartScan(sender.tab.id, sender.tab.url);
        }
    } else if (message.type === 'XSS_DETECTED') {
        // 处理XSS检测结果
        console.log('XSS vulnerability detected:', message.data);
    } else if (message.type === 'SEND_TO_FEISHU') {
        // 处理飞书消息发送
        const { url: webhookUrl, message: feishuMessage } = message.data;
        
        fetch(webhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(feishuMessage)
        })
        .then(response => response.json())
        .then(data => {
            console.log('飞书消息发送成功:', data);
            sendResponse({ success: true, data });
        })
        .catch(error => {
            console.error('飞书消息发送失败:', error);
            sendResponse({ error: error.message });
        });
        
        return true; // 保持消息通道开放以进行异步响应
    }
    return true;
});

// 监听标签页关闭事件
chrome.tabs.onRemoved.addListener((tabId) => {
    // 从就绪列表中移除关闭的标签页
    readyTabs.delete(tabId);
}); 