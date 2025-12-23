# USTC-Passport

分析了统一身份认证的部分代码，用于方便后面写代码自动化登录逻辑。因为自己始终不能触发二次登陆，所以没写二次登陆逻辑。

但其实二次登陆应该也很好处理，不管是TOTP，还是passkey。TOTP直接记录下secret就行。passkey直接使用软件认证器即可。

同时逆向了id.password.ustc.cn的部分js加密逻辑。

脚本中有些字段device一些字段还有risk等，需要自己补充，核心的加密逻辑处理了。

timestamp: 2025.12.24

可能随着系统更新而失效。
