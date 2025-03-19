// 全局变量
let currentConfig = {
    scanTargets: {
        enabled: true,
        targets: [] // 格式: [{domain: "example.com", includeSubdomains: true}]
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

let onlyString = '';
let protocol = '';
let host = '';
let href = '';
let hostPath = '';
let urlPath = [];

// 结果窗口引用
let resultsWindow = null;
let resultsTabId = null;

// 定义多种XSS测试payload
const XSS_PAYLOADS = [
    {
        name: '基础反射型',
        value: (timestamp) => `'"><XSS${timestamp}>`
    },
    {
        name: 'HTML注入',
        value: (timestamp) => `<img src=x onerror=alert(${timestamp})>`
    },
    {
        name: 'JavaScript事件',
        value: (timestamp) => `" onmouseover="alert(${timestamp})`
    },
    {
        name: 'SVG标签',
        value: (timestamp) => `<svg/onload=alert(${timestamp})>`
    },
    {
        name: 'Script标签',
        value: (timestamp) => `<script>alert(${timestamp})</script>`
    }
];

// 加载配置
async function loadConfig() {
    try {
        console.log('开始加载配置...');
        const result = await chrome.storage.local.get('config');
        console.log('从存储中读取的配置:', result);
        
        if (result.config) {
            // 合并配置，确保所有必需的属性都存在
            currentConfig = {
                scanTargets: {
                    enabled: true,
                    targets: [],
                    ...(result.config.scanTargets || {})
                },
                scan: {
                    scanParameters: true,
                    scanHiddenInputs: true,
                    scanPseudoStatic: true,
                    scanForms: true,
                    scanLinks: true,
                    ...(result.config.scan || {})
                },
                notification: {
                    feishu: {
                        enabled: true,
                        webhook: result.config.notification?.feishu?.webhook || ''
                    }
                }
            };
        }

        console.log('处理后的配置:', currentConfig);
        return currentConfig;
    } catch (error) {
        console.error('加载配置时出错:', error);
        // 出错时保持使用默认配置
        return currentConfig;
    }
}

// 打开结果页面
async function openResultsWindow() {
    if (!resultsWindow || resultsWindow.closed) {
        // 使用chrome.tabs.create打开新标签页
        chrome.runtime.sendMessage({ 
            type: 'OPEN_RESULTS_PAGE'
        }, function(response) {
            if (response && response.tabId) {
                resultsTabId = response.tabId;
            }
        });
    }
}

// 发送漏洞信息到飞书
async function addVulnerability(vulnType, url, details) {
    // 处理不同的参数调用方式
    let processedVulnType = vulnType;
    let processedUrl = url;
    let processedDetails = details;

    // 如果传入的是对象，转换成统一格式
    if (typeof vulnType === 'object') {
        const vulnInfo = vulnType;
        processedVulnType = vulnInfo.type;
        processedUrl = vulnInfo.url;
        processedDetails = JSON.stringify({
            parameter: vulnInfo.parameter,
            payload: vulnInfo.payload,
            payloadType: vulnInfo.payloadType,
            description: vulnInfo.description
        }, null, 2);
    }

    // 检查飞书配置
    if (currentConfig.notification.feishu.enabled && currentConfig.notification.feishu.webhook) {
        const webhookUrl = currentConfig.notification.feishu.webhook;
        
        // 构建飞书消息
        const message = {
            "msg_type": "post",
            "content": {
                "post": {
                    "zh_cn": {
                        "title": "发现XSS漏洞",
                        "content": [
                            [
                                {
                                    "tag": "text",
                                    "text": "漏洞类型: "
                                },
                                {
                                    "tag": "text",
                                    "text": processedVulnType
                                }
                            ],
                            [
                                {
                                    "tag": "text",
                                    "text": "URL: "
                                },
                                {
                                    "tag": "text",
                                    "text": processedUrl
                                }
                            ],
                            [
                                {
                                    "tag": "text",
                                    "text": "详细信息:\n"
                                },
                                {
                                    "tag": "text",
                                    "text": processedDetails
                                }
                            ],
                            [
                                {
                                    "tag": "text",
                                    "text": "发现时间: "
                                },
                                {
                                    "tag": "text",
                                    "text": new Date().toLocaleString()
                                }
                            ]
                        ]
                    }
                }
            }
        };

        try {
            console.log('准备发送到飞书:', {
                webhookUrl,
                message
            });

            // 通过 background script 发送请求
            chrome.runtime.sendMessage({
                type: 'SEND_TO_FEISHU',
                data: {
                    url: webhookUrl,
                    message: message
                }
            }, response => {
                if (response && response.error) {
                    console.error('发送到飞书失败:', response.error);
                } else {
                    console.log('成功发送到飞书');
                }
            });
        } catch (error) {
            console.error('发送到飞书时出错:', error);
        }
    } else {
        console.log('飞书通知未启用或未配置webhook URL');
    }

    // 发送到结果页面
    if (resultsTabId) {
        chrome.runtime.sendMessage({
            type: 'ADD_VULNERABILITY',
            data: {
                type: processedVulnType,
                url: processedUrl,
                details: processedDetails,
                timestamp: new Date().toLocaleString()
            }
        });
    }
}

// 通知background script内容脚本已准备就绪
chrome.runtime.sendMessage({ type: 'CONTENT_SCRIPT_READY' });

// 监听来自background script的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'START_SCAN') {
        // 合并接收到的配置
        if (message.config) {
            currentConfig = {
                scanTargets: {
                    enabled: true,
                    targets: [],
                    ...(message.config.scanTargets || {})
                },
                scan: {
                    scanParameters: true,
                    scanHiddenInputs: true,
                    scanPseudoStatic: true,
                    scanForms: true,
                    scanLinks: true,
                    ...(message.config.scan || {})
                },
                notification: {
                    feishu: {
                        enabled: true,
                        webhook: message.config.notification?.feishu?.webhook || ''
                    }
                }
            };
        }
        startScan();
    }
    return true;
});

// 开始扫描
async function startScan() {
    console.log('开始扫描...');
    
    try {
        // 初始化共享变量
        const timestamp = new Date().valueOf();
        onlyString = `'"><XSS${timestamp}>`;
        protocol = window.location.protocol;
        host = window.location.host;
        href = window.location.href;

        // 确保配置已加载
        await loadConfig();

        console.log('使用的配置:', currentConfig);

        // 检查当前域名是否是扫描目标
        if (!isScanTarget(host)) {
            console.log('当前域名不在扫描目标中，跳过扫描:', host);
            return false;
        }

        if(href.indexOf("?") != "-1"){
            hostPath = href.slice(0,href.indexOf("?"));
        }else{
            hostPath = href;
        }
        urlPath = hostPath.split("/").splice(3);

        // 根据配置决定是否扫描
        if(location.search != "" && currentConfig.scan.scanParameters){
            await parameter_Xss();
            if(currentConfig.scan.scanHiddenInputs) {
                await hidden_input_Xss();
            }
        }
        if(href.split("/")[3] != "" && currentConfig.scan.scanPseudoStatic){
            await pseudoStatic_Xss();
        }
        if($("form").length > 0 && currentConfig.scan.scanForms){
            await form_Xss();
        }
        
        // 新增：扫描页面链接
        if (currentConfig.scan.scanLinks) {
            await scanPageLinks();
        }
    } catch (error) {
        console.error('扫描过程中出错:', error);
    }
}

// 检查是否是扫描目标
function isScanTarget(domain) {
    if (!currentConfig?.scanTargets?.enabled || !currentConfig?.scanTargets?.targets?.length) {
        console.log('未配置扫描目标或扫描目标功能未启用');
        return false;
    }

    // 检查是否匹配任一目标域名
    return currentConfig.scanTargets.targets.some(target => {
        if (!target.domain) return false;
        
        if (target.includeSubdomains) {
            // 如果允许子域名，检查域名是否以目标域名结尾
            return domain.endsWith(target.domain);
        }
        // 否则精确匹配域名
        return domain === target.domain;
    });
}

// 修改checkLinkXss函数以支持多个payload
async function checkLinkXss(url, param) {
    try {
        const linkDomain = new URL(url).hostname;
        
        // 检查是否是扫描目标
        if (!isScanTarget(linkDomain)) {
            console.log(`跳过非目标域名: ${linkDomain}`);
            return;
        }

        // 构建测试URL
        const testUrl = new URL(url);
        const paramValue = testUrl.searchParams.get(param);
        if (!paramValue) return;

        // 修复 Mixed Content 问题：将 HTTP 转换为 HTTPS
        if (window.location.protocol === 'https:' && url.startsWith('http:')) {
            url = 'https:' + url.substring(5);
            console.log(`已将 HTTP 转换为 HTTPS: ${url}`);
        }

        // 对每个payload进行测试
        for (const payload of XSS_PAYLOADS) {
            const timestamp = new Date().valueOf();
            const testPayload = payload.value(timestamp);
            
            // 构建测试参数
            testUrl.searchParams.set(param, testPayload);
            const testUrlString = testUrl.toString();

            try {
                // 使用 jQuery AJAX 请求
                const response = await $.ajax({
                    url: testUrlString,
                    type: 'GET',
                    dataType: 'text',
                    timeout: 5000,
                    async: true,
                    xhrFields: {
                        withCredentials: true
                    },
                    headers: {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                });

                // 检查响应中是否包含我们的测试字符串
                if (response && response.indexOf(testPayload) !== -1) {
                    console.log(`发现XSS漏洞 (${payload.name}): ${testUrlString}`);
                    addVulnerability({
                        type: 'XSS',
                        url: url,
                        parameter: param,
                        payload: testPayload,
                        payloadType: payload.name,
                        description: `在链接参数 ${param} 中发现反射型XSS漏洞\n漏洞类型: ${payload.name}\n测试Payload: ${testPayload}`
                    });
                    // 如果找到漏洞，继续测试其他payload
                }
            } catch (ajaxError) {
                // 如果 AJAX 请求失败，尝试使用 Image 对象
                try {
                    await new Promise((resolve, reject) => {
                        const img = new Image();
                        img.onload = () => {
                            // 图片加载成功可能意味着参数被反射
                            console.log(`通过Image检测到可能的XSS (${payload.name}): ${testUrlString}`);
                            addVulnerability({
                                type: 'XSS',
                                url: url,
                                parameter: param,
                                payload: testPayload,
                                payloadType: payload.name,
                                description: `在链接参数 ${param} 中可能存在反射型XSS漏洞\n漏洞类型: ${payload.name}\n测试Payload: ${testPayload}\n检测方法: Image加载`
                            });
                            resolve();
                        };
                        img.onerror = () => resolve(); // 忽略错误，继续检查
                        img.src = testUrlString;

                        // 5秒超时
                        setTimeout(() => resolve(), 5000);
                    });
                } catch (imgError) {
                    console.log(`Image请求也失败 (${payload.name}): ${testUrlString}`, imgError);
                }
            }

            // 在每个payload测试之间添加短暂延迟
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    } catch (error) {
        console.log(`检查链接参数时出错 (${param}):`, error);
    }
}

// 修改其他扫描函数以使用多个payload
function parameter_Xss() {
    var parameter = location.search.substring(1).split("&");
    var url = protocol + "//" + host + "/" + urlPath.join("/") + "?";
    
    parameter.forEach(async (param) => {
        const paramName = param.split("=")[0];
        
        // 对每个payload进行测试
        for (const payload of XSS_PAYLOADS) {
            const timestamp = new Date().valueOf();
            const testPayload = payload.value(timestamp);
            
            const testParams = [...parameter];
            const paramIndex = testParams.findIndex(p => p.startsWith(paramName + '='));
            testParams[paramIndex] = `${paramName}=${testPayload}`;
            
            try {
                const response = await $.ajax({
                    url: url + testParams.join("&"),
                    type: 'get',
                    dataType: 'text',
                    timeout: 5000
                });
                
                if (response.indexOf(testPayload) !== -1) {
                    const vulnDetails = {
                        parameter: paramName,
                        payload: testPayload,
                        payloadType: payload.name,
                        requestUrl: url + testParams.join("&"),
                        requestMethod: 'GET'
                    };
                    addVulnerability(
                        'URL参数XSS',
                        url,
                        JSON.stringify(vulnDetails, null, 2)
                    );
                }
            } catch (error) {
                console.log(`测试payload失败 (${payload.name}):`, error);
            }
            
            // 在每个payload测试之间添加短暂延迟
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    });
}

function pseudoStatic_Xss(){	//伪静态检测XSS
    var fileURL;
    var fileUrlXss;
    var url;
    var xss = "";
    if(urlPath[urlPath.length-1].indexOf(".") != "-1"){
        fileURL = urlPath.pop();
        fileUrlXss = fileURL.split(".")[0] + onlyString + "." + fileURL.split(".")[1]
        $.ajax({
            url: protocol + "//" + host + "/" + urlPath.join("/") + "/" + fileUrlXss,
            type: 'get',
            dataType: 'text',
            async:false,
        })
        .done(function(data) {
            if(data.indexOf(onlyString) != "-1"){
                const vulnDetails = {
                    file: fileURL,
                    requestUrl: protocol + "//" + host + "/" + urlPath.join("/") + "/" + fileUrlXss,
                    requestMethod: 'GET'
                };
                addVulnerability(
                    '伪静态XSS',
                    protocol + "//" + host + "/" + urlPath.join("/") + "/" + fileURL,
                    JSON.stringify(vulnDetails, null, 2)
                );
            }
        })
    }else{
        fileURL = "";
        if(urlPath[urlPath.length-1] == ""){
            urlPath.pop();
        }
    }
    for(var i = 0;i < urlPath.length;i++){
        urlPath[i] += onlyString;
        url = protocol + "//" + host + "/" + urlPath.join("/") + "/" + fileURL;
        $.ajax({
            url: url,
            type: 'get',
            dataType: 'text',
            async:false,
        })
        .done(function(data){
            if(data.indexOf(onlyString) != "-1"){
                xss += urlPath[i].substring(0,urlPath[i].length-11) + "|";
            }
        })
        urlPath[i] = urlPath[i].substring(0,urlPath[i].length-11);
    }
    if(xss == ""){
        return false;
    }else{
        xss = xss.substring(0,xss.length-1);
        alert("当前伪静态路径或者文件" + xss + "存在XSS漏洞");
        console.log(xss)
    }
}

function form_Xss() {
    try {
        var tureForm = $("form").filter(function(item, index) {
            try {
                var imgArray = [];
                $(this).find("img").each(function() {
                    var src = $(this).attr("src");
                    if (src) imgArray.push(src);
                });

                if (imgArray.length > 0) {
                    for (var i = 0; i < imgArray.length; i++) {
                        if (!imgArray[i]) continue;
                        
                        if (imgArray[i].indexOf("?") != "-1") {
                            imgArray[i] = imgArray[i].slice(0, imgArray[i].indexOf("?"));
                        }
                        var ext = imgArray[i].substr(imgArray[i].lastIndexOf("."));
                        if (![".png", ".jpg", ".jpeg", ".gif"].includes(ext)) {
                            return false;
                        }
                    }
                }
                return $(this).find(":input:not(:submit)").length > 0;
            } catch (error) {
                console.log('过滤表单时出错:', error);
                return false;
            }
        });

        if (tureForm.length <= 0) return false;

        tureForm = $(tureForm).filter(function() {
            try {
                var inputs = $(this).find(":input:not(:submit)");
                return inputs.length > 0 && inputs.toArray().some(input => input && input.getAttribute && input.getAttribute("name"));
            } catch (error) {
                console.log('过滤命名表单时出错:', error);
                return false;
            }
        });

        if (tureForm.length <= 0) return false;

        tureForm.each(async function(i) {
            try {
                var $form = $(this);
                var actionUrl = $form.attr("action") || href;
                var methodType = ($form.attr("method") || "get").toLowerCase();
                var inputs = $form.find("input:not(:submit)");
                var sendData = "";

                inputs.each(function(j) {
                    try {
                        var name = $(this).attr("name");
                        if (name) {
                            sendData += name + "=" + onlyString + j + "&";
                        }
                    } catch (error) {
                        console.log('处理表单输入时出错:', error);
                    }
                });

                if (!sendData) return;

                sendData = sendData.slice(0, -1); // 移除最后的 &

                try {
                    // 通过 background script 发送请求
                    chrome.runtime.sendMessage({
                        type: 'SEND_FORM_REQUEST',
                        data: {
                            url: actionUrl,
                            method: methodType,
                            data: sendData
                        }
                    }, async response => {
                        if (response.error) {
                            console.log('发送表单请求时出错:', response.error);
                            return;
                        }

                        const responseData = response.data;
                        var xss = "";
                        inputs.each(function(j) {
                            if (responseData.indexOf(onlyString + j) != "-1") {
                                xss += (j + 1) + "|";
                            }
                        });

                        if (xss) {
                            const vulnDetails = {
                                form: {
                                    action: actionUrl,
                                    method: methodType
                                },
                                vulnerableInputs: xss.split('|')
                                    .filter(Boolean)
                                    .map(index => {
                                        const input = inputs.eq(parseInt(index) - 1);
                                        return {
                                            index: parseInt(index),
                                            name: input.attr("name") || ''
                                        };
                                    }),
                                requestData: sendData
                            };
                            await addVulnerability(
                                '表单XSS',
                                actionUrl,
                                JSON.stringify(vulnDetails, null, 2)
                            );
                        }
                    });
                } catch (error) {
                    console.log('发送表单请求时出错:', error);
                }
            } catch (error) {
                console.log('处理表单时出错:', error);
            }
        });
    } catch (error) {
        console.error('表单扫描时出错:', error);
    }
}

function hidden_input_Xss() {
    try {
        var parameter = [];
        var inputs = $("input[type=hidden]");
        var url = protocol + "//" + host + "/" + urlPath.join("/") + "?";

        if (inputs.length > 0) {
            inputs.each(function() {
                try {
                    var name = $(this).attr("name") || $(this).attr("id");
                    if (name) {
                        parameter.push(name);
                    }
                } catch (error) {
                    console.log('处理隐藏输入框时出错:', error);
                }
            });
        }

        parameter.forEach(async (param, i) => {
            try {
                var testParam = param + "=" + onlyString;
                
                try {
                    const response = await $.ajax({
                        url: url + testParam,
                        type: 'GET',
                        dataType: 'text',
                        async: true,
                        timeout: 5000,
                        xhrFields: {
                            withCredentials: true
                        }
                    });

                    if (response.indexOf(onlyString) != "-1") {
                        const vulnDetails = {
                            parameter: param,
                            requestUrl: url + testParam,
                            requestMethod: 'GET',
                            inputType: 'hidden'
                        };
                        await addVulnerability(
                            'Hidden输入框XSS',
                            url,
                            JSON.stringify(vulnDetails, null, 2)
                        );
                    }
                } catch (error) {
                    console.log('发送隐藏输入框请求时出错:', error);
                }
            } catch (error) {
                console.log('处理隐藏输入框参数时出错:', error);
            }
        });
    } catch (error) {
        console.error('隐藏输入框扫描时出错:', error);
    }
}

// 扫描页面链接和资源
async function scanPageLinks() {
    console.log('开始扫描页面链接和资源...');
    
    // 扫描所有链接
    const links = $('a[href]');
    let totalLinks = links.length;
    let skippedLinks = 0;
    let scannedLinks = 0;
    let crossDomainLinks = 0;
    let errorLinks = 0;

    console.log(`找到 ${totalLinks} 个链接`);

    // 扫描所有表单
    const forms = $('form');
    console.log(`找到 ${forms.length} 个表单`);

    // 扫描所有iframe
    const iframes = $('iframe[src]');
    console.log(`找到 ${iframes.length} 个iframe`);

    // 扫描所有script标签
    const scripts = $('script[src]');
    console.log(`找到 ${scripts.length} 个外部脚本`);

    // 扫描所有图片
    const images = $('img[src]');
    console.log(`找到 ${images.length} 个图片`);

    // 合并所有需要扫描的资源
    const allResources = [
        ...Array.from(links).map(link => ({ type: 'link', url: $(link).attr('href') })),
        ...Array.from(forms).map(form => ({ type: 'form', url: $(form).attr('action') })),
        ...Array.from(iframes).map(iframe => ({ type: 'iframe', url: $(iframe).attr('src') })),
        ...Array.from(scripts).map(script => ({ type: 'script', url: $(script).attr('src') })),
        ...Array.from(images).map(img => ({ type: 'image', url: $(img).attr('src') }))
    ].filter(resource => resource.url); // 过滤掉没有URL的资源

    console.log(`总共找到 ${allResources.length} 个资源需要扫描`);

    // 使用Promise.all和并发控制来加速扫描
    const batchSize = 1; // 单个请求处理以避免过多并发
    for (let i = 0; i < allResources.length; i += batchSize) {
        const batch = allResources.slice(i, i + batchSize);
        const promises = batch.map(async (resource) => {
            let url = resource.url;
            
            try {
                // 检查是否是有效的URL
                if (!url || url.startsWith('javascript:') || url.startsWith('#') || url === 'javascript:;') {
                    skippedLinks++;
                    return;
                }

                // 将相对路径转换为完整URL
                try {
                    // 修复URL格式问题
                    if (url.startsWith('//')) {
                        url = window.location.protocol + url;
                    } else if (url.startsWith('/')) {
                        url = window.location.origin + url;
                    } else if (!url.match(/^https?:\/\//)) {
                        url = new URL(url, window.location.href).href;
                    }

                    // 修复 Mixed Content 问题：将 HTTP 转换为 HTTPS
                    if (window.location.protocol === 'https:' && url.startsWith('http:')) {
                        url = 'https:' + url.substring(5);
                    }
                } catch (urlError) {
                    console.log(`无效的URL格式: ${url}`);
                    skippedLinks++;
                    return;
                }

                // 检查URL是否有效
                if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    console.log(`跳过非HTTP(S) URL: ${url}`);
                    skippedLinks++;
                    return;
                }

                const resourceDomain = new URL(url).hostname;
                
                // 检查是否是扫描目标
                if (!isScanTarget(resourceDomain)) {
                    console.log(`跳过非目标域名: ${resourceDomain}`);
                    skippedLinks++;
                    return;
                }

                // 对于跨域资源，增加计数
                if (resourceDomain !== window.location.hostname) {
                    crossDomainLinks++;
                }

                // 检查URL参数
                const urlObj = new URL(url);
                const params = urlObj.searchParams;
                
                for (const [param, value] of params.entries()) {
                    if (value && value.length > 0) {
                        await checkLinkXss(url, param);
                    }
                }
                
                scannedLinks++;
            } catch (error) {
                console.log(`处理${resource.type}时出错: ${url}`, error);
                errorLinks++;
            }
        });

        // 等待当前批次完成
        await Promise.all(promises);
        // 增加延迟以避免请求过于频繁
        await new Promise(resolve => setTimeout(resolve, 2000));
    }

    console.log(`资源扫描完成:
    - 总资源数: ${allResources.length}
    - 已扫描: ${scannedLinks}
    - 已跳过: ${skippedLinks}
    - 跨域资源: ${crossDomainLinks}
    - 错误资源: ${errorLinks}
    - 资源类型: 链接、表单、iframe、脚本、图片
    - 跳过原因: 非目标域名或无效URL`);
}

// 初始化
document.addEventListener('DOMContentLoaded', async () => {
    console.log('内容脚本已加载');
    // 通知后台脚本内容脚本已准备就绪
    chrome.runtime.sendMessage({ type: 'CONTENT_SCRIPT_READY' });
    
    // 开始扫描
    await startScan();
}); 