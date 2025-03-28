# AutoXSS: 高级 XSS 漏洞侦测与利用引擎

## 渗透测试利器 | 一键式 XSS 猎手 | 漏洞验证平台

**AutoXSS** 是一款强大的浏览器扩展式渗透测试工具，专为安全研究人员、白帽黑客和 Web 应用防御者打造。它能在您浏览网页的同时，自动识别、验证并利用潜在的跨站脚本 (XSS) 漏洞，使您能够在攻击者之前发现并修复安全漏洞。

### 核心功能

🔥 **实时漏洞侦测**：以隐蔽模式运行，在您浏览的每个页面中自动扫描 XSS 攻击面，包括 URL 参数、表单字段、HTTP 请求和 DOM 操作。

⚡ **多向量攻击模拟**：集成前沿的 XSS 有效载荷库，能够模拟反射型、存储型和 DOM 型 XSS 攻击，突破传统防御机制。

🛡️ **先进验证引擎**：通过无害化执行验证确认真实漏洞，消除误报，提供详细的漏洞证据和专业安全分析。

🔍 **深度渗透分析**：自动探测目标域的子域名，分析 HTTP 和 HTTPS 流量，执行多层次参数注入测试，揭示隐藏的安全弱点。

### 为黑客和安全专家设计

- **精确目标管理**：自定义扫描目标和排除项，专注于高价值资产
- **隐蔽操作模式**：维持低调的浏览器资源利用率，避免被检测系统识别
- **即时威胁情报**：直接集成飞书 Webhook，实时接收高危漏洞警报
- **漏洞证据记录**：自动生成详细的攻击向量文档，附带利用建议
- **一键式开关控制**：随时启停渗透功能，无需复杂配置

### 从网络世界的守护者，到入侵测试先锋

FireAutoXSS 将复杂的漏洞研究过程集成于简洁的界面中，让每一次网络冲浪都变成一次渗透测试。当其他人只是浏览网页时，您已经悄然完成了整个安全评估。无论是企业安全团队的日常监控，还是白帽黑客的漏洞赏金猎取，这款工具都能让您领先一步。

**警告**：这款工具具有强大的漏洞发现能力，仅供合法安全测试使用。使用者应确保已获得目标系统的明确授权。未经授权的安全测试可能违反法律法规。

---

## 技术概述

- 高级payload生成与自动变形技术
- 智能DOM遍历与注入点识别
- 多阶段漏洞验证与确认
- 基于DOM状态的实时漏洞触发
- 加密通信通道与安全报告机制

---

*"当每个网页都是一个待解的谜题，FireAutoXSS就是您手中的解密工具。"*

<details>
<summary><b>🐍谷歌浏览器-google</b></summary>

## 配置目标域
📞 **第一步**：打开浏览器开发者模式
📂 **第二步**：直接拖动文件夹
🔧 **第三步**：配置目标域名，定义Webhook地址，配置完成后点击开始扫描
🕒 **第四步**：等待扫描完成，扫描完成后会自动发送到Webhook地址
🔍 **第五步**：安全工程师收到消息后进行人工复测
![image](https://github.com/user-attachments/assets/0a7bf343-e1e4-4c9c-affa-d49f2af44411)

![image](https://github.com/user-attachments/assets/11ba8601-5b12-4fa5-9109-027e30bbc4e6)

## 效果图
![image](https://github.com/user-attachments/assets/4add7df7-faa5-44e5-9e83-b694a37bd6e7)

</details>

<details>
<summary><b>🐍火狐浏览器-firefox</b></summary>

## 配置目标域
## 安装

1. 下载 fireautoxss.xpi 文件
2. 在 Firefox 中，打开 about:addons 页面
3. 点击右上角的齿轮图标，选择"从文件安装附加组件"
4. 选择下载的 .xpi 文件
5. 确认安装提示

## 配置

1. 安装后，点击 Firefox 工具栏上的 FireAutoXSS 图标，或在 about:addons 页面中点击扩展的"选项"按钮
2. 在设置页面中：
   - 添加扫描目标域名（如果不添加任何域名，将扫描所有网站）
   - 配置一个或多个飞书 Webhook URLs 用于接收漏洞报告
   - 设置其他扫描选项（自动扫描、主动测试等）
3. 点击"保存设置"按钮

## 使用

1. 浏览网页时，扩展会根据您的设置自动扫描 XSS 漏洞
2. 发现漏洞时，会自动发送通知到您配置的飞书 Webhook
3. 您可以在飞书中查看详细的漏洞报告

## 高级功能

- **主动测试**：启用后，扩展会尝试在 URL 参数中插入特定标记来检测 XSS 漏洞
- **批处理大小**：控制一次发送的漏洞数量
- **漏洞历史清除**：允许重新报告之前已发送过的漏洞

## 注意事项

- 主动测试功能可能会改变页面行为，请谨慎使用
- 确保配置了有效的飞书 Webhook 地址，否则无法接收漏洞报告

![image](https://github.com/user-attachments/assets/296f8d25-3c25-44fe-aee8-f9d0dcba0607)

![image](https://github.com/user-attachments/assets/96e5a46f-5ac0-4a1d-b0ee-65ec29b20d51)
</details>


## Stargazers over time
[![Stargazers over time](https://starchart.cc/rassec1/autoxss.svg?variant=adaptive)](https://starchart.cc/rassec1/autoxss)
