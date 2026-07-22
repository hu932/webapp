# Ajie Android Plugin

这是 Ajie 的 Android 端。

## 工作流程

1. App 登录服务器插件账号：`api1_login`。
2. App 在 WebView 里登录目标站，保存 Cookie。
3. App 请求服务器拉任务：`api1_take`。
4. App 把任务 URL + WebView Cookie 发给服务器：`android_session_fetch_submit`。
5. 服务器使用这个 Cookie 请求任务页，再把结果提交到上游。

## 说明

- App 不再显示服务器后台管理员密码 / `X-Auth-Key`。
- 服务器的任务账号池、并发、设备授权、日志都在 `decrypt_proxy.php` 控制。
- App 只保存：服务器地址、插件账号、插件密码、WebView 登录页。

## 构建

仓库推送后由 GitHub Actions 自动执行 Android 构建。

产物：`android-plugin/app/build/outputs/apk/debug/*.apk`
