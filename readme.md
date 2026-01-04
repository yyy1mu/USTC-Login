# USTC-Passport

## Update: 2025.12.24

分析了统一身份认证的部分代码，用于方便后面写代码自动化登录逻辑。因为自己始终不能触发二次登陆，所以没写二次登陆逻辑。

但其实二次登陆应该也很好处理，不管是TOTP，还是passkey。TOTP直接记录下secret就行。passkey直接使用软件认证器即可。

同时逆向了id.password.ustc.cn的部分js加密逻辑。

可能随着系统更新而失效。

## Update: 2025.12.25

完成了device、riskpayload所有的参数模拟，现在您只需要修改monitor—auto-with-riskpayload中的账号和密码，以及services参数即可拿到登录到任意系统的cookie。

monitor—auto-with-riskpayload 会在本地生成一些参数信息，这是为了信任设备有所保留的。

## Update: 2026.01.04 

现在的脚本已经完成了bypass的二次验证逻辑（相比于脚本，使用比较正常的环境参数，比如UA）。这个更新日志日志主要是记录TOTP的逻辑。

/cas/api/protected/otpAuthn/verifyToken获取登录的一次行token，在下一个请求中需要  
/cas/login type=otpLogin，password=TOTP，token ; trustDevice=True(该参数可以使用totp登录方法将本设备保存为信任设备，这样我们就可以将现在的环境参数设置为可信设备，下一步就不要二次验证)  


该项目接受pr，您可以提供service参数出的网站URL，供我们测试。

## TODO-list

* [ ] TOTP 由于现在网站二次校验逻辑比较宽松，开发者很难调出TOTP，后续可能会更新
* [ ] WebAuthn 估计没有时间更新