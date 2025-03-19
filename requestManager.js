import { ConfigManager } from './config.js';

class RequestManager {
    constructor() {
        this.requestQueue = [];
        this.processing = false;
        this.requestCount = 0;
        this.lastRequestTime = 0;
        this.config = null;
        this.cache = new Map();
    }

    async initialize() {
        this.config = await ConfigManager.load();
        this.startProcessing();
    }

    // 请求限制检查
    checkRequestLimit() {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        const requestsPerMinute = this.requestCount;

        // 检查请求频率
        if (timeSinceLastRequest < this.config.requestLimit.requestDelay) {
            return false;
        }

        // 检查每分钟请求数
        if (requestsPerMinute >= this.config.requestLimit.maxRequestsPerMinute) {
            return false;
        }

        // 检查并发请求数
        if (this.requestQueue.length >= this.config.requestLimit.maxConcurrentRequests) {
            return false;
        }

        return true;
    }

    // 缓存管理
    getCachedResponse(url) {
        if (!this.config.cache.enabled) return null;

        const cached = this.cache.get(url);
        if (!cached) return null;

        if (Date.now() - cached.timestamp > this.config.cache.ttl) {
            this.cache.delete(url);
            return null;
        }

        return cached.data;
    }

    setCachedResponse(url, data) {
        if (!this.config.cache.enabled) return;

        // 检查缓存大小
        if (this.cache.size >= this.config.cache.maxSize) {
            const oldestKey = Array.from(this.cache.entries())
                .sort(([, a], [, b]) => a.timestamp - b.timestamp)[0][0];
            this.cache.delete(oldestKey);
        }

        this.cache.set(url, {
            data,
            timestamp: Date.now()
        });
    }

    // 请求队列管理
    async addRequest(request) {
        if (!this.checkRequestLimit()) {
            this.requestQueue.push(request);
            return;
        }

        try {
            await this.processRequest(request);
        } catch (error) {
            console.error('Request processing error:', error);
            if (request.retryCount < this.config.performance.requestQueue.retryAttempts) {
                request.retryCount++;
                this.requestQueue.push(request);
            }
        }
    }

    async processRequest(request) {
        this.lastRequestTime = Date.now();
        this.requestCount++;

        // 检查缓存
        const cachedResponse = this.getCachedResponse(request.url);
        if (cachedResponse) {
            return cachedResponse;
        }

        // 发送请求
        const response = await fetch(request.url, {
            method: request.method,
            headers: request.headers,
            body: request.body
        });

        // 处理响应
        const data = await response.text();
        
        // 缓存响应
        this.setCachedResponse(request.url, data);

        return data;
    }

    // 队列处理
    async startProcessing() {
        if (this.processing) return;
        this.processing = true;

        while (this.processing) {
            if (this.requestQueue.length > 0) {
                const batch = this.requestQueue.splice(0, this.config.performance.requestQueue.batchSize);
                await Promise.all(batch.map(request => this.processRequest(request)));
            }

            // 等待一段时间再处理下一批
            await new Promise(resolve => setTimeout(resolve, this.config.requestLimit.requestDelay));
        }
    }

    stopProcessing() {
        this.processing = false;
    }

    // 请求签名验证
    generateRequestSignature(request) {
        const { url, method, headers, body } = request;
        const signatureData = `${method}:${url}:${JSON.stringify(headers)}:${body}`;
        return btoa(signatureData);
    }

    // 敏感信息过滤
    filterSensitiveData(data) {
        const { patterns, excludePatterns } = this.config.security.sensitiveData;
        
        let filteredData = data;
        for (const pattern of patterns) {
            if (!excludePatterns.some(exclude => exclude.test(pattern))) {
                filteredData = filteredData.replace(pattern, '[REDACTED]');
            }
        }
        
        return filteredData;
    }

    // 访问控制检查
    checkAccessControl(request) {
        const { requireAuth, allowedMethods, maxPayloadSize } = this.config.security.accessControl;

        // 检查请求方法
        if (!allowedMethods.includes(request.method)) {
            throw new Error('Method not allowed');
        }

        // 检查认证要求
        if (requireAuth && !request.headers['Authorization']) {
            throw new Error('Authentication required');
        }

        // 检查负载大小
        if (request.body && request.body.length > maxPayloadSize) {
            throw new Error('Payload too large');
        }

        return true;
    }
}

export const requestManager = new RequestManager(); 