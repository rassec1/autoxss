// 当前配置
let currentConfig = null;

// 默认配置
const defaultConfig = {
    whitelist: {
        enabled: true,
        domains: [],
        includeSubdomains: true
    },
    scanTargets: {
        enabled: true,
        targets: []
    },
    scan: {
        scanParameters: true,
        scanHiddenInputs: true,
        scanPseudoStatic: true,
        scanForms: true,
        scanLinks: true
    },
    notification: {
        feishu: {
            enabled: true,
            webhook: ''
        }
    }
};

// DOM 元素
const elements = {
    scanTargets: document.getElementById('scanTargets'),
    whitelist: document.getElementById('whitelist'),
    addScanTarget: document.getElementById('addScanTarget'),
    addWhitelist: document.getElementById('addWhitelist'),
    save: document.getElementById('save'),
    status: document.getElementById('status'),
    scanTargetsEnabled: document.getElementById('scanTargetsEnabled'),
    whitelistEnabled: document.getElementById('whitelistEnabled'),
    includeSubdomains: document.getElementById('includeSubdomains'),
    scanParameters: document.getElementById('scanParameters'),
    scanHiddenInputs: document.getElementById('scanHiddenInputs'),
    scanPseudoStatic: document.getElementById('scanPseudoStatic'),
    scanForms: document.getElementById('scanForms'),
    scanLinks: document.getElementById('scanLinks'),
    feishuEnabled: document.getElementById('feishuEnabled'),
    feishuWebhook: document.getElementById('feishuWebhook')
};

// 初始化页面
document.addEventListener('DOMContentLoaded', async () => {
    console.log('页面加载完成，开始初始化...');
    
    // 加载当前配置
    const configManager = new ConfigManager();
    currentConfig = await configManager.load();
    console.log('当前配置:', currentConfig);
    
    // 显示扫描域名
    if (currentConfig.scanTargets && currentConfig.scanTargets.targets) {
        console.log('加载扫描域名:', currentConfig.scanTargets.targets);
        currentConfig.scanTargets.targets.forEach(target => {
            addDomainToList('scan-domains', {
                domain: target.domain,
                includeSubdomains: target.includeSubdomains
            });
        });
    }

    // 显示白名单域名
    if (currentConfig.whitelist && currentConfig.whitelist.domains) {
        console.log('加载白名单域名:', currentConfig.whitelist.domains);
        currentConfig.whitelist.domains.forEach(domain => {
            addDomainToList('whitelist-domains', {
                domain: domain,
                includeSubdomains: currentConfig.whitelist.includeSubdomains
            });
        });
    }

    // 确保函数在全局范围可用
    window.addScanDomain = addScanDomain;
    window.addWhitelistDomain = addWhitelistDomain;
    window.saveConfig = saveConfig;
    
    // 绑定按钮事件
    document.getElementById('add-scan-domain').addEventListener('click', addScanDomain);
    document.getElementById('add-whitelist-domain').addEventListener('click', addWhitelistDomain);
    document.getElementById('save-config').addEventListener('click', saveConfig);
    
    console.log('初始化完成');
});

// 配置管理器类
class ConfigManager {
    constructor() {
        this.config = null;
    }

    async load() {
        try {
            console.log('开始加载配置...');
            const result = await chrome.storage.local.get('config');
            console.log('从存储中读取的配置:', result);
            this.config = result.config || defaultConfig;
            return this.config;
        } catch (error) {
            console.error('加载配置时出错:', error);
            return null;
        }
    }

    async save(config) {
        try {
            console.log('开始保存配置:', config);
            await chrome.storage.local.set({ config });
            this.config = config;
            console.log('配置保存成功');
            return true;
        } catch (error) {
            console.error('保存配置时出错:', error);
            return false;
        }
    }
}

// 添加扫描域名
function addScanDomain() {
    console.log('添加扫描域名');
    addDomainToList('scan-domains', {
        domain: '',
        includeSubdomains: true
    });
}

// 添加白名单域名
function addWhitelistDomain() {
    console.log('添加白名单域名');
    addDomainToList('whitelist-domains', {
        domain: '',
        includeSubdomains: true
    });
}

// 添加域名到列表
function addDomainToList(listId, domainInfo) {
    console.log('添加域名到列表:', listId, domainInfo);
    const list = document.getElementById(listId);
    const item = document.createElement('div');
    item.className = 'domain-item';
    
    const input = document.createElement('input');
    input.type = 'text';
    input.value = domainInfo.domain;
    input.placeholder = '输入域名 (例如: example.com)';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.checked = domainInfo.includeSubdomains;
    
    const label = document.createElement('label');
    label.textContent = '包含子域名';
    
    const removeButton = document.createElement('button');
    removeButton.textContent = '删除';
    removeButton.className = 'remove';
    
    // 使用addEventListener而不是onclick
    removeButton.addEventListener('click', () => {
        item.remove();
        showStatus('已删除域名', 'success');
    });
    
    item.appendChild(input);
    item.appendChild(checkbox);
    item.appendChild(label);
    item.appendChild(removeButton);
    
    list.appendChild(item);
}

// 从列表中获取域名配置
function getDomainListConfig(listId) {
    console.log('获取域名列表配置:', listId);
    const list = document.getElementById(listId);
    const items = list.getElementsByClassName('domain-item');
    const domains = [];
    
    for (const item of items) {
        const domain = item.querySelector('input[type="text"]').value.trim();
        if (domain) {
            if (listId === 'scan-domains') {
                domains.push({
                    domain: domain,
                    includeSubdomains: item.querySelector('input[type="checkbox"]').checked,
                    paths: ['/'],
                    excludePaths: [],
                    methods: ['GET', 'POST'],
                    parameters: {
                        include: ['*'],
                        exclude: []
                    }
                });
            } else {
                domains.push(domain);
            }
        }
    }
    
    console.log('获取到的域名配置:', domains);
    return domains;
}

// 显示状态消息
function showStatus(message, isError = false) {
    elements.status.textContent = message;
    elements.status.className = `status-message ${isError ? 'error' : 'success'}`;
    elements.status.style.display = 'block';
    setTimeout(() => {
        elements.status.style.display = 'none';
    }, 3000);
}

// 加载配置
async function loadConfig() {
    try {
        const result = await chrome.storage.local.get('config');
        const config = result.config || defaultConfig;
        
        // 加载扫描目标
        elements.scanTargetsEnabled.checked = config.scanTargets.enabled;
        config.scanTargets.targets.forEach(target => {
            createDomainInput(target.domain, elements.scanTargets);
        });
        
        // 加载白名单
        elements.whitelistEnabled.checked = config.whitelist.enabled;
        elements.includeSubdomains.checked = config.whitelist.includeSubdomains;
        config.whitelist.domains.forEach(domain => {
            createDomainInput(domain, elements.whitelist);
        });
        
        // 加载扫描选项
        elements.scanParameters.checked = config.scan.scanParameters;
        elements.scanHiddenInputs.checked = config.scan.scanHiddenInputs;
        elements.scanPseudoStatic.checked = config.scan.scanPseudoStatic;
        elements.scanForms.checked = config.scan.scanForms;
        elements.scanLinks.checked = config.scan.scanLinks;
        
        // 加载飞书配置
        elements.feishuEnabled.checked = config.notification.feishu.enabled;
        elements.feishuWebhook.value = config.notification.feishu.webhook;
        
    } catch (error) {
        console.error('加载配置时出错:', error);
        showStatus('加载配置失败', true);
    }
}

// 保存配置
async function saveConfig() {
    try {
        const config = {
            whitelist: {
                enabled: elements.whitelistEnabled.checked,
                domains: Array.from(elements.whitelist.querySelectorAll('input[type="text"]'))
                    .map(input => input.value.trim())
                    .filter(domain => domain),
                includeSubdomains: elements.includeSubdomains.checked
            },
            scanTargets: {
                enabled: elements.scanTargetsEnabled.checked,
                targets: Array.from(elements.scanTargets.querySelectorAll('input[type="text"]'))
                    .map(input => ({
                        domain: input.value.trim(),
                        includeSubdomains: true
                    }))
                    .filter(target => target.domain)
            },
            scan: {
                scanParameters: elements.scanParameters.checked,
                scanHiddenInputs: elements.scanHiddenInputs.checked,
                scanPseudoStatic: elements.scanPseudoStatic.checked,
                scanForms: elements.scanForms.checked,
                scanLinks: elements.scanLinks.checked
            },
            notification: {
                feishu: {
                    enabled: elements.feishuEnabled.checked,
                    webhook: elements.feishuWebhook.value.trim()
                }
            }
        };
        
        await chrome.storage.local.set({ config });
        showStatus('配置已保存');
        
        // 通知后台脚本配置已更新
        chrome.runtime.sendMessage({ type: 'CONFIG_UPDATED', config });
        
    } catch (error) {
        console.error('保存配置时出错:', error);
        showStatus('保存配置失败', true);
    }
}

// 创建域名输入项
function createDomainInput(domain = '', list) {
    const item = document.createElement('div');
    item.className = 'domain-item';
    
    const input = document.createElement('input');
    input.type = 'text';
    input.value = domain;
    input.placeholder = '请输入域名';
    
    const removeButton = document.createElement('button');
    removeButton.textContent = '删除';
    removeButton.onclick = () => item.remove();
    
    item.appendChild(input);
    item.appendChild(removeButton);
    list.appendChild(item);
}

// 事件监听器
elements.addScanTarget.addEventListener('click', () => createDomainInput('', elements.scanTargets));
elements.addWhitelist.addEventListener('click', () => createDomainInput('', elements.whitelist));
elements.save.addEventListener('click', saveConfig);

// 初始化
document.addEventListener('DOMContentLoaded', loadConfig); 