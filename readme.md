# USTC-Passport

## Update: 2025.12.24

分析了统一身份认证的部分代码，用于方便后面写代码自动化登录逻辑。因为自己始终不能触发二次登陆，所以没写二次登陆逻辑。

但其实二次登陆应该也很好处理，不管是TOTP，还是passkey。TOTP直接记录下secret就行。passkey直接使用软件认证器即可。

同时逆向了id.password.ustc.cn的部分js加密逻辑。

可能随着系统更新而失效。

## Update: 2025.12.25

完成了device、riskpayload所有的参数模拟，现在您只需要修改monitor—auto-with-riskpayload中的账号和密码，以及services参数即可拿到登录到任意系统的cookie。

monitor—auto-with-riskpayload 会在本地生成一些参数信息，这是为了信任设备有所保留的。