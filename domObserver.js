import { ConfigManager } from './config.js';
import { xssDetector } from './xssDetector.js';

class DOMObserver {
    constructor() {
        this.config = null;
        this.observer = null;
        this.mutationQueue = [];
        this.processing = false;
        this.frameworkDetector = null;
    }

    async initialize() {
        this.config = await ConfigManager.load();
        this.initializeFrameworkDetector();
        this.startObserving();
    }

    // 初始化框架检测器
    initializeFrameworkDetector() {
        this.frameworkDetector = {
            detectVue() {
                return !!window.__VUE__;
            },
            detectReact() {
                return !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
            },
            detectAngular() {
                return !!window.angular;
            },
            detectSvelte() {
                return !!window.__svelte;
            }
        };
    }

    // 开始观察DOM变化
    startObserving() {
        const { throttle, batchSize, maxDepth } = this.config.performance.domObserver;

        this.observer = new MutationObserver((mutations) => {
            // 将变化添加到队列
            this.mutationQueue.push(...mutations);

            // 使用节流处理队列
            if (!this.processing) {
                this.processMutationQueue();
            }
        });

        // 配置观察选项
        const options = {
            childList: true,      // 观察子节点的添加和删除
            subtree: true,        // 观察所有后代节点
            attributes: true,     // 观察属性变化
            characterData: true,  // 观察文本内容变化
            attributeFilter: ['value', 'innerHTML', 'textContent'] // 只观察特定属性
        };

        // 开始观察
        this.observer.observe(document.documentElement, options);
    }

    // 处理变化队列
    async processMutationQueue() {
        if (this.mutationQueue.length === 0) return;

        this.processing = true;

        // 获取一批变化进行处理
        const batch = this.mutationQueue.splice(0, this.config.performance.domObserver.batchSize);

        // 处理每个变化
        for (const mutation of batch) {
            await this.processMutation(mutation);
        }

        // 等待节流时间
        await new Promise(resolve => 
            setTimeout(resolve, this.config.performance.domObserver.throttle)
        );

        this.processing = false;

        // 如果队列中还有变化，继续处理
        if (this.mutationQueue.length > 0) {
            this.processMutationQueue();
        }
    }

    // 处理单个变化
    async processMutation(mutation) {
        // 处理添加的节点
        for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
                await this.analyzeNode(node);
            }
        }

        // 处理属性变化
        if (mutation.type === 'attributes') {
            await this.analyzeAttributeChange(mutation.target, mutation.attributeName);
        }

        // 处理文本内容变化
        if (mutation.type === 'characterData') {
            await this.analyzeTextContent(mutation.target);
        }
    }

    // 分析节点
    async analyzeNode(node, depth = 0) {
        if (depth > this.config.performance.domObserver.maxDepth) return;

        // 检查框架特定的注入点
        if (this.detectFramework()) {
            await this.analyzeFrameworkSpecific(node);
        }

        // 分析节点属性
        for (const attr of node.attributes) {
            await this.analyzeAttribute(node, attr);
        }

        // 分析子节点
        for (const child of node.children) {
            await this.analyzeNode(child, depth + 1);
        }
    }

    // 分析属性
    async analyzeAttribute(node, attribute) {
        const { name, value } = attribute;

        // 检查敏感属性
        if (this.isSensitiveAttribute(name)) {
            const result = await xssDetector.detectXSS(value, {
                type: 'attribute',
                name: name,
                node: node
            });

            if (result) {
                this.reportVulnerability(result);
            }
        }
    }

    // 分析属性变化
    async analyzeAttributeChange(node, attributeName) {
        if (this.isSensitiveAttribute(attributeName)) {
            const value = node.getAttribute(attributeName);
            const result = await xssDetector.detectXSS(value, {
                type: 'attribute',
                name: attributeName,
                node: node
            });

            if (result) {
                this.reportVulnerability(result);
            }
        }
    }

    // 分析文本内容
    async analyzeTextContent(node) {
        const result = await xssDetector.detectXSS(node.textContent, {
            type: 'text',
            node: node
        });

        if (result) {
            this.reportVulnerability(result);
        }
    }

    // 分析框架特定的注入点
    async analyzeFrameworkSpecific(node) {
        // Vue特定分析
        if (this.frameworkDetector.detectVue()) {
            await this.analyzeVueNode(node);
        }

        // React特定分析
        if (this.frameworkDetector.detectReact()) {
            await this.analyzeReactNode(node);
        }

        // Angular特定分析
        if (this.frameworkDetector.detectAngular()) {
            await this.analyzeAngularNode(node);
        }

        // Svelte特定分析
        if (this.frameworkDetector.detectSvelte()) {
            await this.analyzeSvelteNode(node);
        }
    }

    // 检测使用的框架
    detectFramework() {
        return Object.values(this.frameworkDetector).some(detector => detector());
    }

    // 检查敏感属性
    isSensitiveAttribute(name) {
        const sensitiveAttributes = [
            'innerHTML',
            'outerHTML',
            'value',
            'src',
            'href',
            'data-*',
            'v-html',    // Vue
            'dangerouslySetInnerHTML', // React
            'ng-bind-html' // Angular
        ];

        return sensitiveAttributes.some(attr => 
            name === attr || name.startsWith('data-') || 
            name.startsWith('v-') || name.startsWith('ng-')
        );
    }

    // 报告漏洞
    reportVulnerability(result) {
        // 这里实现漏洞报告逻辑
        console.log('XSS Vulnerability detected:', result);
        
        // 可以添加视觉提示
        this.highlightVulnerableElement(result.context.node);
    }

    // 高亮显示易受攻击的元素
    highlightVulnerableElement(node) {
        const originalStyle = node.style.cssText;
        node.style.cssText = `
            ${originalStyle}
            outline: 3px solid red !important;
            animation: xss-warning 1s infinite;
        `;

        // 添加警告动画
        const style = document.createElement('style');
        style.textContent = `
            @keyframes xss-warning {
                0% { outline-color: red; }
                50% { outline-color: yellow; }
                100% { outline-color: red; }
            }
        `;
        document.head.appendChild(style);

        // 3秒后移除高亮
        setTimeout(() => {
            node.style.cssText = originalStyle;
            style.remove();
        }, 3000);
    }

    // 停止观察
    stopObserving() {
        if (this.observer) {
            this.observer.disconnect();
            this.observer = null;
        }
        this.mutationQueue = [];
        this.processing = false;
    }
}

export const domObserver = new DOMObserver(); 