// 获取当前标签页
async function getCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
}

// 更新扫描状态
async function updateScanStatus(isActive) {
    const statusDiv = document.getElementById('status');
    statusDiv.textContent = isActive ? 'Scanner is active' : 'Scanner is inactive';
    statusDiv.className = `status ${isActive ? 'active' : 'inactive'}`;
}

// 初始化弹出窗口
document.addEventListener('DOMContentLoaded', async () => {
    const tab = await getCurrentTab();
    
    // 获取当前扫描状态
    chrome.storage.local.get(['scanActive'], (result) => {
        updateScanStatus(result.scanActive !== false);
    });

    // 切换扫描状态
    document.getElementById('toggleScan').addEventListener('click', async () => {
        const currentStatus = document.getElementById('status').classList.contains('active');
        const newStatus = !currentStatus;
        
        // 更新存储中的状态
        await chrome.storage.local.set({ scanActive: newStatus });
        
        // 更新UI
        updateScanStatus(newStatus);
        
        // 通知content script
        chrome.tabs.sendMessage(tab.id, {
            type: 'TOGGLE_SCAN',
            active: newStatus
        });
    });

    // 查看结果
    document.getElementById('viewResults').addEventListener('click', async () => {
        // 获取扫描结果
        chrome.storage.local.get(['scanResults'], (result) => {
            const results = result.scanResults || [];
            if (results.length === 0) {
                alert('No vulnerabilities found yet.');
                return;
            }
            
            // 显示结果
            const resultsText = results.map(r => 
                `URL: ${r.url}\nType: ${r.type}\nParameter: ${r.parameter}\nSeverity: ${r.severity}`
            ).join('\n\n');
            
            alert(resultsText);
        });
    });
}); 