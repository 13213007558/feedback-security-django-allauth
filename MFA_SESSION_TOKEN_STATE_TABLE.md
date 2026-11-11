# Headless 会话令牌在 MFA 中间态的实际权限（端到端验证）

验证对象：本仓库 `allauth.headless`（django-allauth 65.21.1 基线），app 客户端
（`X-Session-Token` 机制只对 `Client.APP` 生效，见
`allauth/headless/internal/sessionkit.py:24`）。

结论先行：**密码正确但 MFA 未完成时，响应里的 `meta.session_token` 只是一个
「匿名会话句柄」，不是登录凭证。** 它指向的 Django 会话没有 `_auth_user_id`，
只在 `account_login` 键里暂存了一个未完成的 `Login` 对象。任何受保护接口都拿
它当匿名请求处理，两种 token strategy 都不会在该状态签发 access token。前端
不能以「拿到 session token」作为登录完成的判据。

## 一、状态表（与真实 HTTP 响应、测试调用一一对应）

下表响应体由真实 HTTP 往返抓取（路径前缀 `/_allauth/app/v1`），对应测试见
`tests/apps/headless/mfa/test_mfa_pending_session_token.py`。
`PT` = 密码登录后、MFA 未完成时拿到的 pending token；`FT` = MFA 成功后轮换出
来的新 token。

| # | 调用（方法 + 路径 + 凭证） | HTTP | `meta.is_authenticated` | 令牌字段 | 关键 data / errors | 会话状态 | 对应测试 |
|---|---|---|---|---|---|---|---|
| S0 | `GET /auth/session`（无 token，全新客户端） | 401 | `false` | 无 | 仅可用 flows，无 pending | 无会话 | `test_confirm_without_any_pending_stage_is_unauthorized` |
| S1 | `POST /auth/login`（密码正确，用户开了 TOTP） | 401 | `false` | 只有 `session_token=PT`，**无 access_token** | flows 含 `mfa_authenticate, is_pending=true, types=[totp]`；无 `user` | 匿名，仅暂存 `account_login` | `test_login_response_is_pending_not_authenticated` |
| S2 | `GET /auth/session`（带 PT） | 401 | `false` | 无新增 | 同样的 pending `mfa_authenticate` | 仍匿名 | `test_session_token_alone_cannot_reach_protected_endpoints` |
| S2b | `GET /account/authenticators/totp`（带 PT，受保护接口） | 401 | `false` | 无 | pending `mfa_authenticate` | 仍匿名 | 同上 |
| S2c | `POST /account/password/change`（带 PT，受保护写接口） | 401 | `false` | 无 | pending `mfa_authenticate`，密码未被修改 | 仍匿名 | 同上 |
| S3 | `POST /auth/2fa/authenticate`（带 PT，错误 code） | 400 | 响应无 `meta` 键 | 无任何令牌 | `errors=[{param:code, code:incorrect_code, message:"Incorrect code."}]` | 阶段保持 pending | `test_wrong_mfa_code_keeps_stage_pending` |
| S3b | 重复 S3（再次/多次错误 code） | 400 | 响应无 `meta` 键 | 无 | 同 S3 | 阶段不被推进，PT 不变 | 同上 |
| S4 | `POST /auth/2fa/authenticate`（另一个全新会话，无挑战） | 401 | `null` | 无 | 普通 flows，无 pending | 无 `account_login` 可进入 | `test_confirm_without_any_pending_stage_is_unauthorized` |
| S4b | 会话 B 拿会话 A 的 PT 去 confirm | 400 | 响应无 `meta` 键 | 无 | `incorrect_code`；A 的挑战原样保留 | 挑战按会话隔离，A 仍 pending | `test_other_session_cannot_consume_challenge` |
| S5 | `GET /auth/session`（不存在/已销毁的 token） | 410 | `null` | 无 | 普通 flows | `lookup_session` 落空，`UnauthorizedResponse(status=410)` | `test_destroyed_session_token_returns_410`、`test_never_known_token_returns_410` |
| S5t | 暂存的 `Login` 超过 `ACCOUNT_LOGIN_TIMEOUT` 后再 confirm | 401 | `false` | 无 | pending flow 消失（`unstash_login` 已清空 `account_login`） | 挑战过期，需重新登录 | `test_login_timeout_expires_challenge` |
| S6 | `POST /auth/2fa/authenticate`（带 PT，正确 code） | 200 | `true` | `session_token=FT`（与 PT 不同）；默认 session strategy 下无 access_token | `data.user` + `methods=[password, mfa(totp)]`，无 flows | 真正登录，写入 `_auth_user_id`，清除 `account_login` | `test_successful_mfa_completes_login` |
| S7 | `GET /auth/session`（登录后再用旧 PT） | 410 | `null` | 无 | 普通 flows | Django 登录轮换了 session key，PT 已失效，无法冒充 | 同上 |
| S8 | `GET /auth/session`（带 FT） | 200 | `true` | 无新增（已认证不再回发 token） | `data.user` | 完整登录态 | 同上 |
| S8b | `GET /account/authenticators/totp`（带 FT） | 200 | — | — | TOTP 数据 | 完整登录态 | 同上 |

### JWT token strategy（`HEADLESS_TOKEN_STRATEGY=...jwt.JWTTokenStrategy`）

| # | 调用 | HTTP | `meta.is_authenticated` | 令牌字段 | 对应测试 |
|---|---|---|---|---|---|
| J1 | `POST /auth/login`（密码正确、MFA 未完成） | 401 | `false` | 只有 `session_token`，**无 access_token / refresh_token** | `test_jwt_pending_state_issues_no_access_token` |
| J2 | `POST /tokens/refresh`（带 PT，伪造 refresh_token） | 400 | — | 拿不到任何 access token | 同上 |
| J3 | `POST /auth/2fa/authenticate`（正确 code） | 200 | `true` | 此时才签发 `access_token` + `refresh_token`，且 `session_token` 轮换 | `test_jwt_access_token_only_after_completed_mfa` |
| J4 | `GET /auth/session`（`Authorization: Bearer <J3 的 access_token>`） | 200 | `true` | bearer 凭证可访问受保护 API | 同上 |

## 二、中间态为什么拿不到任何「完整登录」能力

1. 认证上下文按 token 重建会话，且只认会话不认令牌语义：
   `authentication_context` 每次用 `lookup_session(token)` 取回 Django 会话
   （`allauth/headless/internal/authkit.py:52`）；查不到会话直接抛
   `ImmediateHttpResponse(UnauthorizedResponse(status=410))`
   （`allauth/headless/internal/authkit.py:67`）——这就是 S5/S7 的 410。
2. 受保护视图统一走 `AuthenticatedAPIView`：`request.user` 未认证就返回
   `AuthenticationResponse`（401），根本进不了业务逻辑
   （`allauth/headless/base/views.py:57`）。MFA 中间态会话没有
   `_auth_user_id`，所以 S2/S2b/S2c 全部 401。
3. access token 只在「匿名 → 认证」跃迁时签发：`expose_access_token` 先要求
   `request.user.is_authenticated`，再要求与请求前用户不同
   （`allauth/headless/internal/authkit.py:83`）。MFA 未完成时 user 始终是
   `AnonymousUser`，默认 session strategy 的 `create_access_token` 本就返回
   `None`（`allauth/headless/tokens/strategies/base.py:29`），JWT strategy 同样
   被这道闸拦住（J1 无 token，J3 才有）。
4. 确认接口不能被「重复访问」跳过：`AuthenticationStageAPIView.handle` 用
   `LoginStageController.enter(request, AuthenticateStage.key)` 进入阶段，进不
   去就 401（`allauth/headless/base/views.py:38`）；输入校验失败返回 400 且
   不调用 `stage.exit()`，阶段状态原样保留（S3/S3b）。挑战存在会话里
   （`account_login`），另一个会话没有这份数据，进不了同一阶段（S4/S4b）。
5. 登录成功会轮换会话：`resume_login` → Django `login()` 触发 session cycle，
   新 key 通过 `expose_session_token` 回发为 FT，旧 PT 立即失效（S6/S7）。

## 三、前端应依据什么判断「登录完成」

- 唯一判据：认证类响应（`/auth/login`、`/auth/2fa/authenticate`、`/auth/session`）
  中 **HTTP 200 且 `meta.is_authenticated === true` 且 `data.user` 存在**。
  本场景里只有 S6/J3（正确 MFA 之后）满足。
- `meta.session_token` 是流程续期句柄，任何阶段（包括 401 中间态）都可能出现，
  **绝不能**作为登录完成或路由放行的依据；它只用于在下一次请求头
  `X-Session-Token` 里带回，以继续未完成的 flow。
- 状态机分支建议：
  - `200 + is_authenticated=true` → 登录完成，保存最新 `session_token`
    （JWT strategy 下同时保存 `access_token`/`refresh_token`，二者只在此刻出现）。
  - `401 + flows[].is_pending`（如 `mfa_authenticate`）→ 登录进行中，按 pending
    flow 渲染对应挑战界面，继续带同一个 `X-Session-Token`。
  - `400`（如 `incorrect_code`）→ 当前阶段输入错误，停留在原阶段重试，不要切换
    登录状态。
  - `410` → 会话句柄已失效/过期/被轮换，清空本地令牌并重新走登录。
  - `401 + is_authenticated=null` 且无 pending flow → 根本没有进行中的流程，
    回到登录入口。
- 后端兜底已验证：即便前端误判，中间态 token 也访问不到任何受保护接口，也换不
  出 access token；但前端仍应按上述判据实现，避免把用户错误地放进已登录视图。

## 四、复现方式

```sh
.venv/bin/python -m pytest -q -o addopts= \
  tests/apps/headless/mfa/test_mfa_pending_session_token.py
```

结果：11 个 app 场景全部通过（browser 参数化用例自动 skip，因为 session token
不面向 browser 客户端）。相邻回归：
`.venv/bin/python -m pytest -q tests/apps/headless/mfa tests/apps/headless/tokens tests/apps/headless/base`
→ 161 passed, 11 skipped。
