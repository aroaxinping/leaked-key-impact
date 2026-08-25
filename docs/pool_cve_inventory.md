# Pool infrastructure — CVE inventory

Vulnerabilities on the proxy-pool egress nodes, from Shodan InternetDB (passive). CVSS/EPSS/KEV from Shodan CVEDB. **EPSS** = estimated probability of exploitation; **KEV** = CISA Known-Exploited (confirmed exploited in the wild).

- Unique CVEs: **205** across **5** IPs

- Severity: 🔴 Critical 35 · 🟠 High 92 · 🟡 Medium 72 · 🟢 Low 5 · ⚠️ KEV 5


## Affected IPs

| IP | Org | Shodan tags | # CVEs |
|---|---|---|---:|
| `103.130.61.61` | PT. Fiqran Solusindo Mediatama | proxy | 186 |
| `45.66.249.187` | RIPE Network Coordination Centre | eol-product,open-dir | 65 |
| `88.150.154.27` | iomart Hosting Limited | proxy,vpn | 61 |
| `2.26.160.172` | NetGrid Host LTD | eol-product | 2 |
| `31.76.31.55` | PowerRDP Network LTD | eol-product | 2 |

## All CVEs, ranked by severity

| CVSS | Band | EPSS | KEV | CVE | Summary |
|---:|---|---:|:--:|---|---|
| 10.0 | Crítica | 99% |  | CVE-2025-62168 | Squid is a caching proxy for the Web. In Squid versions prior to 7.2, a fai |
| 9.9 | Crítica | 93% |  | CVE-2020-15049 | An issue was discovered in http/ContentLengthInterpreter.cc in Squid before |
| 9.8 | Crítica | 100% |  | CVE-2021-44790 | A carefully crafted request body can cause a buffer overflow in the mod_lua |
| 9.8 | Crítica | 100% |  | CVE-2023-25690 | Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through  |
| 9.8 | Crítica | 99% |  | CVE-2021-26691 | In Apache HTTP Server versions 2.4.0 to 2.4.46 a specially crafted SessionH |
| 9.8 | Crítica | 99% |  | CVE-2022-23943 | Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows a |
| 9.8 | Crítica | 99% |  | CVE-2024-38476 | Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerab |
| 9.8 | Crítica | 99% |  | CVE-2021-39275 | ap_escape_quotes() may write beyond the end of a buffer when given maliciou |
| 9.8 | Crítica | 98% |  | CVE-2017-7679 | In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_mime can r |
| 9.8 | Crítica | 98% |  | CVE-2022-22720 | Apache HTTP Server 2.4.52 and earlier fails to close inbound connection whe |
| 9.8 | Crítica | 98% |  | CVE-2020-11945 | An issue was discovered in Squid before 5.0.2. A remote attacker can replay |
| 9.8 | Crítica | 98% |  | CVE-2019-12525 | An issue was discovered in Squid 3.3.9 through 3.5.28 and 4.x through 4.7.  |
| 9.8 | Crítica | 97% |  | CVE-2019-12526 | An issue was discovered in Squid before 4.9. URN response handling in Squid |
| 9.8 | Crítica | 97% |  | CVE-2017-3167 | In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_ |
| 9.8 | Crítica | 97% |  | CVE-2017-3169 | In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, mod_ssl may de |
| 9.8 | Crítica | 97% |  | CVE-2018-1312 | In Apache httpd 2.2.0 to 2.4.29, when generating an HTTP Digest authenticat |
| 9.8 | Crítica | 93% |  | CVE-2019-12519 | An issue was discovered in Squid through 4.7. When handling the tag esi:whe |
| 9.8 | Crítica | 90% |  | CVE-2019-12524 | An issue was discovered in Squid through 4.7. When handling requests from u |
| 9.8 | Crítica | 88% |  | CVE-2022-31813 | Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* header |
| 9.8 | Crítica | 83% |  | CVE-2024-38474 | Substitution encoding issue in mod_rewrite in Apache HTTP Server 2.4.59 and |
| 9.8 | Crítica | 70% |  | CVE-2026-28780 | Heap-based Buffer Overflow vulnerability in mod_proxy_ajp of Apache HTTP Se |
| 9.8 | Crítica | 50% |  | CVE-2026-29167 | Use After Free vulnerability in Apache HTTP Server with mod_ldap in per-dir |
| 9.8 | Crítica | 41% |  | CVE-2026-44631 | Buffer Underwrite vulnerability in Apache HTTP Server on crafted regular ex |
| 9.3 | Crítica | 98% |  | CVE-2025-54574 | Squid is a caching proxy for the Web. In versions 6.3 and below, Squid is v |
| 9.3 | Crítica | 93% |  | CVE-2023-46846 | SQUID is vulnerable to HTTP request smuggling, caused by chunked decoder le |
| 9.1 | Crítica | 100% | ⚠️ | CVE-2024-38475 | Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and |
| 9.1 | Crítica | 99% |  | CVE-2017-9788 | In Apache httpd before 2.2.34 and 2.4.x before 2.4.27, the value placeholde |
| 9.1 | Crítica | 99% |  | CVE-2022-22721 | If LimitXMLRequestBody is set to allow request bodies larger than 350MB (de |
| 9.1 | Crítica | 97% |  | CVE-2019-10082 | In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 |
| 9.1 | Crítica | 93% |  | CVE-2022-28615 | Apache HTTP Server 2.4.53 and earlier may crash or disclose information due |
| 9.1 | Crítica | 90% |  | CVE-2019-12523 | An issue was discovered in Squid before 4.9. When handling a URN request, a |
| 9.1 | Crítica | 60% |  | CVE-2025-23048 | In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4. |
| 9.1 | Crítica | 43% |  | CVE-2026-42535 | A path handling issue in mod_dav_fs in Apache 2.4.67 and earlier allows a W |
| 9.0 | Crítica | 100% | ⚠️ | CVE-2021-40438 | A crafted request uri-path can cause mod_proxy to forward the request to an |
| 9.0 | Crítica | 78% |  | CVE-2022-36760 | Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vul |
| 8.8 | Alta | 98% |  | CVE-2016-4051 | Buffer overflow in cachemgr.cgi in Squid 2.x, 3.x before 3.5.17, and 4.x be |
| 8.8 | Alta | 48% |  | CVE-2026-24072 | An escalation of privilege bug in various modules in Apache HTTP 2.4.66 and |
| 8.6 | Alta | 100% |  | CVE-2023-49285 | Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. |
| 8.6 | Alta | 100% |  | CVE-2023-46847 | Squid is vulnerable to a Denial of Service,  where a remote attacker can pe |
| 8.6 | Alta | 100% |  | CVE-2016-4553 | client_side.cc in Squid before 3.5.18 and 4.x before 4.0.10 does not proper |
| 8.6 | Alta | 99% |  | CVE-2024-25111 | Squid is a web proxy cache. Starting in version 3.5.27 and prior to version |
| 8.6 | Alta | 99% |  | CVE-2023-50269 | Squid is a caching proxy for the Web. Due to an Uncontrolled Recursion bug  |
| 8.6 | Alta | 99% |  | CVE-2016-4554 | mime_header.cc in Squid before 3.5.18 allows remote attackers to bypass int |
| 8.6 | Alta | 95% |  | CVE-2023-49286 | Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. |
| 8.6 | Alta | 95% |  | CVE-2020-25097 | An issue was discovered in Squid through 4.13 and 5.x through 5.0.4. Due to |
| 8.6 | Alta | 92% |  | CVE-2020-24606 | Squid before 4.13 and 5.x before 5.0.4 allows a trusted peer to perform Den |
| 8.6 | Alta | 91% |  | CVE-2023-49288 | Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. |
| 8.6 | Alta | 90% |  | CVE-2023-46724 | Squid is a caching proxy for the Web. Due to an Improper Validation of Spec |
| 8.6 | Alta | 85% |  | CVE-2022-41318 | A buffer over-read was discovered in libntlmauth in Squid 2.5 through 5.6.  |
| 8.3 | Alta | 72% |  | CVE-2025-58098 | Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabl |
| 8.2 | Alta | 100% |  | CVE-2021-44224 | A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on |
| 8.2 | Alta | 98% |  | CVE-2016-3947 | Heap-based buffer overflow in the Icmp6::Recv function in icmp/Icmp6.cc in  |
| 8.1 | Alta | 100% |  | CVE-2016-4054 | Buffer overflow in Squid 3.x before 3.5.17 and 4.x before 4.0.9 allows remo |
| 8.1 | Alta | 100% |  | CVE-2017-15715 | In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> c |
| 8.1 | Alta | 99% |  | CVE-2016-5387 | The Apache HTTP Server through 2.4.23 follows RFC 3875 section 4.1.18 and t |
| 8.1 | Alta | 98% |  | CVE-2024-38473 | Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier allo |
| 8.1 | Alta | 96% |  | CVE-2016-4052 | Multiple stack-based buffer overflows in Squid 3.x before 3.5.17 and 4.x be |
| 7.8 | Alta | 99% | ⚠️ | CVE-2019-0211 | In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker |
| 7.5 | Alta | 100% | ⚠️ | CVE-2023-44487 | The HTTP/2 protocol allows a denial of service (server resource consumption |
| 7.5 | Alta | 100% |  | CVE-2017-9798 | Apache httpd allows remote attackers to read secret data from process memor |
| 7.5 | Alta | 100% |  | CVE-2024-27316 | HTTP/2 incoming headers exceeding the limit are temporarily buffered in ngh |
| 7.5 | Alta | 100% |  | CVE-2016-8740 | The mod_http2 module in the Apache HTTP Server 2.4.17 through 2.4.23, when  |
| 7.5 | Alta | 99% |  | CVE-2022-22719 | A carefully crafted request body can cause a read to a random memory area w |
| 7.5 | Alta | 99% |  | CVE-2024-38472 | SSRF in Apache HTTP Server on Windows allows to potentially leak NTLM hashe |
| 7.5 | Alta | 99% |  | CVE-2018-1303 | A specially crafted HTTP request header could have crashed the Apache HTTP  |
| 7.5 | Alta | 99% |  | CVE-2021-34798 | Malformed requests may cause the server to dereference a NULL pointer. This |
| 7.5 | Alta | 99% |  | CVE-2021-26690 | Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Cookie head |
| 7.5 | Alta | 99% |  | CVE-2016-4555 | client_side_request.cc in Squid 3.x before 3.5.18 and 4.x before 4.0.10 all |
| 7.5 | Alta | 99% |  | CVE-2024-45802 | Squid is an open source caching proxy for the Web supporting HTTP, HTTPS, F |
| 7.5 | Alta | 99% |  | CVE-2021-33193 | A crafted method sent through HTTP/2 will bypass validation and be forwarde |
| 7.5 | Alta | 99% |  | CVE-2019-18679 | An issue was discovered in Squid 2.x, 3.x, and 4.x through 4.8. Due to inco |
| 7.5 | Alta | 98% |  | CVE-2016-3948 | Squid 3.x before 3.5.16 and 4.x before 4.0.8 improperly perform bounds chec |
| 7.5 | Alta | 98% |  | CVE-2024-39573 | Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allo |
| 7.5 | Alta | 98% |  | CVE-2026-49975 | Memory Allocation with Excessive Size Value vulnerability in Apache HTTP Se |
| 7.5 | Alta | 98% |  | CVE-2016-4556 | Double free vulnerability in Esi.cc in Squid 3.x before 3.5.18 and 4.x befo |
| 7.5 | Alta | 97% |  | CVE-2022-26377 | Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vul |
| 7.5 | Alta | 97% |  | CVE-2018-17199 | In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the  |
| 7.5 | Alta | 97% |  | CVE-2016-4979 | The Apache HTTP Server 2.4.18 through 2.4.20, when mod_http2 and mod_ssl ar |
| 7.5 | Alta | 97% |  | CVE-2019-0217 | In Apache HTTP Server 2.4 release 2.4.38 and prior, a race condition in mod |
| 7.5 | Alta | 97% |  | CVE-2017-15710 | In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod |
| 7.5 | Alta | 97% |  | CVE-2018-1333 | By specially crafting HTTP/2 requests, workers would be allocated 60 second |
| 7.5 | Alta | 96% |  | CVE-2016-8743 | Apache HTTP Server, in all releases prior to 2.2.32 and 2.4.25, was liberal |
| 7.5 | Alta | 96% |  | CVE-2013-4365 | Heap-based buffer overflow in the fcgid_header_bucket_read function in fcgi |
| 7.5 | Alta | 96% |  | CVE-2018-1000027 | The Squid Software Foundation Squid HTTP Caching Proxy version prior to ver |
| 7.5 | Alta | 95% |  | CVE-2019-12528 | An issue was discovered in Squid before 4.10. It allows a crafted FTP serve |
| 7.5 | Alta | 95% |  | CVE-2019-18676 | An issue was discovered in Squid 3.x and 4.x through 4.8. Due to incorrect  |
| 7.5 | Alta | 95% |  | CVE-2026-33526 | Squid is a caching proxy for the Web. Prior to version 7.5, due to heap Use |
| 7.5 | Alta | 95% |  | CVE-2026-32748 | Squid is a caching proxy for the Web. Prior to version 7.5, due to prematur |
| 7.5 | Alta | 95% |  | CVE-2020-8449 | An issue was discovered in Squid before 4.10. Due to incorrect input valida |
| 7.5 | Alta | 94% |  | CVE-2018-1000024 | The Squid Software Foundation Squid HTTP Caching Proxy version 3.0 to 3.5.2 |
| 7.5 | Alta | 94% |  | CVE-2021-28651 | An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a |
| 7.5 | Alta | 94% |  | CVE-2020-8517 | An issue was discovered in Squid before 4.10. Due to incorrect input valida |
| 7.5 | Alta | 93% |  | CVE-2016-10002 | Incorrect processing of responses to If-None-Modified HTTP conditional requ |
| 7.5 | Alta | 93% |  | CVE-2022-29404 | In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua scri |
| 7.5 | Alta | 93% |  | CVE-2023-46728 | Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. |
| 7.5 | Alta | 93% |  | CVE-2007-4723 | Directory traversal vulnerability in Ragnarok Online Control Panel 4.3.4a,  |
| 7.5 | Alta | 92% |  | CVE-2011-2688 | SQL injection vulnerability in mysql/mysql-auth.pl in the mod_authnz_extern |
| 7.5 | Alta | 92% |  | CVE-2022-30556 | Apache HTTP Server 2.4.53 and earlier may return lengths to applications ca |
| 7.5 | Alta | 92% |  | CVE-2023-5824 | A flaw was found in Squid. The limits applied for validation of HTTP respon |
| 7.5 | Alta | 91% |  | CVE-2025-53020 | Late Release of Memory after Effective Lifetime vulnerability in Apache HTT |
| 7.5 | Alta | 91% |  | CVE-2016-10003 | Incorrect HTTP Request header comparison in Squid HTTP Proxy 3.5.0.1 throug |
| 7.5 | Alta | 89% |  | CVE-2019-12520 | An issue was discovered in Squid through 4.7 and 5. When receiving a reques |
| 7.5 | Alta | 88% |  | CVE-2006-20001 | A carefully crafted If: request header can cause a memory read, or write of |
| 7.5 | Alta | 87% |  | CVE-2024-38477 | null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earl |
| 7.5 | Alta | 86% |  | CVE-2023-31122 | Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This is |
| 7.5 | Alta | 84% |  | CVE-2020-14058 | An issue was discovered in Squid before 4.12 and 5.x before 5.0.3. Due to u |
| 7.5 | Alta | 73% |  | CVE-2024-40898 | SSRF in Apache HTTP Server on Windows with mod_rewrite in server/vhost cont |
| 7.5 | Alta | 66% |  | CVE-2025-49630 | In certain proxy configurations, a denial of service attack against Apache  |
| 7.5 | Alta | 64% |  | CVE-2026-34355 | A buffer overflow in mod_proxy_html in Apache HTTP Server 2.4.67 and earlie |
| 7.5 | Alta | 64% |  | CVE-2024-43394 | Server-Side Request Forgery (SSRF) in Apache HTTP Server on Windows allows  |
| 7.5 | Alta | 61% |  | CVE-2026-42536 | Heap-based Buffer Overflow vulnerability in Apache HTTP Server with mod_xml |
| 7.5 | Alta | 54% |  | CVE-2024-43204 | SSRF in Apache HTTP Server with mod_proxy loaded allows an attacker to send |
| 7.5 | Alta | 54% |  | CVE-2025-59775 | Server-Side Request Forgery (SSRF) vulnerability 

 in Apache HTTP Server o |
| 7.5 | Alta | 51% |  | CVE-2024-42516 | HTTP response splitting in the core of Apache HTTP Server allows an attacke |
| 7.5 | Alta | 51% |  | CVE-2026-34356 | Heap-based Buffer Overflow vulnerability in Apache HTTP Server with malicio |
| 7.5 | Alta | 50% |  | CVE-2024-47252 | Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Serve |
| 7.5 | Alta | 46% |  | CVE-2026-29169 | A NULL pointer dereference in mod_dav_lock in Apache HTTP Server 2.4.66 and |
| 7.5 | Alta | 37% |  | CVE-2025-55753 | An integer overflow in the case of failed ACME certificate renewal leads, a |
| 7.5 | Alta | 32% |  | CVE-2026-34059 | Buffer Over-read vulnerability in Apache HTTP Server.

This issue affects A |
| 7.4 | Alta | 43% |  | CVE-2025-49812 | In some mod_ssl configurations on Apache HTTP Server versions through to 2. |
| 7.3 | Alta | 99% |  | CVE-2020-8450 | An issue was discovered in Squid before 4.10. Due to incorrect buffer manag |
| 7.3 | Alta | 99% |  | CVE-2020-35452 | Apache HTTP Server versions 2.4.0 to 2.4.46 A specially crafted Digest nonc |
| 7.3 | Alta | 90% |  | CVE-2023-38709 | Faulty input validation in the core of Apache allows malicious or exploitab |
| 7.3 | Alta | 52% |  | CVE-2026-44185 | Buffer Over-read vulnerability in Apache HTTP Server via outbound OCSP requ |
| 7.3 | Alta | 47% |  | CVE-2026-29168 | Allocation of Resources Without Limits or Throttling vulnerability in Apach |
| 7.3 | Alta | 45% |  | CVE-2026-44186 | Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in the |
| 7.3 | Alta | 39% |  | CVE-2026-48913 | Use After Free vulnerability in Apache HTTP Server module mod_http2 when fi |
| 6.9 | Media | 100% |  | CVE-2020-11022 | In jQuery starting with 1.12.0 and before 3.5.0, passing HTML from untruste |
| 6.9 | Media | 100% | ⚠️ | CVE-2020-11023 | In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing |
| 6.5 | Media | 100% |  | CVE-2021-31806 | An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a |
| 6.5 | Media | 100% |  | CVE-2021-33620 | Squid before 4.15 and 5.x before 5.0.6 allows remote servers to cause a den |
| 6.5 | Media | 97% |  | CVE-2021-31807 | An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. An integ |
| 6.5 | Media | 92% |  | CVE-2021-31808 | An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to a |
| 6.5 | Media | 91% |  | CVE-2021-46784 | In Squid 3.x through 3.5.28, 4.x through 4.17, and 5.x before 5.6, due to i |
| 6.5 | Media | 90% |  | CVE-2020-15811 | An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to i |
| 6.5 | Media | 84% |  | CVE-2020-15810 | An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to i |
| 6.5 | Media | 72% |  | CVE-2026-47729 | Squid is a caching proxy for the Web. Prior to 7.6, due to an improper vali |
| 6.5 | Media | 61% |  | CVE-2026-33515 | Squid is a caching proxy for the Web. Prior to version 7.5, due to improper |
| 6.5 | Media | 53% |  | CVE-2025-65082 | Improper Neutralization of Escape, Meta, or Control Sequences vulnerability |
| 6.5 | Media | 43% |  | CVE-2026-43951 | Out-of-bounds Read vulnerability in Apache HTTP Server with mod_headers and |
| 6.5 | Media | 36% |  | CVE-2026-33523 | HTTP response splitting vulnerability in multiple Apache HTTP Server module |
| 6.3 | Media | 93% |  | CVE-2024-37894 | Squid is a caching proxy for the Web supporting HTTP, HTTPS, FTP, and more. |
| 6.3 | Media | 86% |  | CVE-2024-24795 | HTTP Response splitting in multiple modules in Apache HTTP Server allows an |
| 6.1 | Media | 100% |  | CVE-2019-11358 | jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, m |
| 6.1 | Media | 100% |  | CVE-2019-10092 | In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue wa |
| 6.1 | Media | 100% |  | CVE-2019-13345 | The cachemgr.cgi web module of Squid through 4.7 has XSS via the user_name  |
| 6.1 | Media | 99% |  | CVE-2019-10098 | In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrit |
| 6.1 | Media | 99% |  | CVE-2020-1927 | In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrit |
| 6.1 | Media | 98% |  | CVE-2015-9251 | jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks whe |
| 6.1 | Media | 98% |  | CVE-2016-4975 | Possible CRLF injection allowing HTTP response splitting attacks for sites  |
| 6.1 | Media | 94% |  | CVE-2019-18677 | An issue was discovered in Squid 3.x and 4.x through 4.8 when the append_do |
| 6.1 | Media | 92% |  | CVE-2019-18860 | Squid before 4.9, when certain web browsers are used, mishandles HTML in th |
| 6.1 | Media | 90% |  | CVE-2018-19131 | Squid before 4.4 has XSS via a crafted X.509 certificate during HTTP(S) err |
| 6.1 | Media | 42% |  | CVE-2026-29170 | A cross-site scripting vulnerability exists in mod_proxy_ftp's HTML directo |
| 5.9 | Media | 99% |  | CVE-2018-11763 | In Apache HTTP Server 2.4.17 to 2.4.34, by sending continuous, large SETTIN |
| 5.9 | Media | 98% |  | CVE-2016-2390 | The FwdState::connectedToPeer method in FwdState.cc in Squid before 3.5.14  |
| 5.9 | Media | 97% |  | CVE-2016-1546 | The Apache HTTP Server 2.4.17 and 2.4.18, when mod_http2 is enabled, does n |
| 5.9 | Media | 96% |  | CVE-2018-1301 | A specially crafted request could have crashed the Apache HTTP Server prior |
| 5.9 | Media | 96% |  | CVE-2018-1302 | When an HTTP/2 stream was destroyed after being handled, the Apache HTTP Se |
| 5.9 | Media | 96% |  | CVE-2018-1172 | This vulnerability allows remote attackers to deny service on vulnerable in |
| 5.9 | Media | 94% |  | CVE-2019-12529 | An issue was discovered in Squid 2.x through 2.7.STABLE9, 3.x through 3.5.2 |
| 5.9 | Media | 93% |  | CVE-2018-19132 | Squid before 4.4, when SNMP is enabled, allows a denial of service (Memory  |
| 5.9 | Media | 93% |  | CVE-2019-12521 | An issue was discovered in Squid through 4.7. When Squid is parsing ESI, it |
| 5.9 | Media | 86% |  | CVE-2023-45802 | When a HTTP/2 stream was reset (RST frame) by a client, there was a time wi |
| 5.9 | Media | 72% |  | CVE-2021-32791 | mod_auth_openidc is an authentication/authorization module for the Apache 2 |
| 5.5 | Media | 96% |  | CVE-2020-13938 | Apache HTTP Server versions 2.4.0 to 2.4.46 Unprivileged local users can st |
| 5.5 | Media | 69% |  | CVE-2026-50012 | Squid is a caching proxy for the Web. Prior to 7.6, due to an improper inpu |
| 5.5 | Media | 7% |  | CVE-2026-44119 | Improper Privilege Management vulnerability in Apache HTTP Server 2.4.67 an |
| 5.4 | Media | 75% |  | CVE-2024-36387 | Serving WebSocket protocol upgrades over a HTTP/2 connection could result i |
| 5.4 | Media | 48% |  | CVE-2025-66200 | mod_userdir+suexec bypass via AllowOverride FileInfo vulnerability in Apach |
| 5.3 | Media | 100% |  | CVE-2024-25617 | Squid is an open source caching proxy for the Web supporting HTTP, HTTPS, F |
| 5.3 | Media | 99% |  | CVE-2019-17567 | Apache HTTP Server versions 2.4.6 to 2.4.46 mod_proxy_wstunnel configured o |
| 5.3 | Media | 99% |  | CVE-2022-37436 | Prior to Apache HTTP Server 2.4.55, a malicious backend can cause the respo |
| 5.3 | Media | 99% |  | CVE-2020-1934 | In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized  |
| 5.3 | Media | 97% |  | CVE-2019-0220 | A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When the p |
| 5.3 | Media | 97% |  | CVE-2019-0196 | A vulnerability was found in Apache HTTP Server 2.4.17 to 2.4.38. Using fuz |
| 5.3 | Media | 97% |  | CVE-2018-17189 | In Apache HTTP server versions 2.4.37 and prior, by sending request bodies  |
| 5.3 | Media | 96% |  | CVE-2019-18678 | An issue was discovered in Squid 3.x and 4.x through 4.8. It allows attacke |
| 5.3 | Media | 95% |  | CVE-2018-1283 | In Apache httpd 2.4.0 to 2.4.29, when mod_session is configured to forward  |
| 5.3 | Media | 94% |  | CVE-2020-11985 | IP address spoofing when proxying using mod_remoteip and mod_rewrite For co |
| 5.3 | Media | 92% |  | CVE-2022-28614 | The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read  |
| 5.3 | Media | 89% |  | CVE-2022-28330 | Apache HTTP Server 2.4.53 and earlier on Windows may read beyond bounds whe |
| 5.3 | Media | 85% |  | CVE-2021-32785 | mod_auth_openidc is an authentication/authorization module for the Apache 2 |
| 5.3 | Media | 42% |  | CVE-2026-33007 | A NULL pointer dereference in the mod_authn_socache in Apache HTTP Server 2 |
| 5.3 | Media | 40% |  | CVE-2026-34032 | Improper Null Termination, Out-of-bounds Read vulnerability in Apache HTTP  |
| 5.3 | Media | 32% |  | CVE-2026-33857 | Out-of-bounds Read vulnerability in mod_proxy_ajp of 

Apache HTTP Server.
 |
| 5.0 | Media | 96% |  | CVE-2013-2765 | The ModSecurity module before 2.7.4 for the Apache HTTP Server allows remot |
| 5.0 | Media | 94% |  | CVE-2012-3526 | The reverse proxy add forward module (mod_rpaf) 0.5 and 0.6 for the Apache  |
| 5.0 | Media | 90% |  | CVE-2009-2299 | The Artofdefence Hyperguard Web Application Firewall (WAF) module before 2. |
| 5.0 | Media | 50% |  | CVE-2012-4001 | The mod_pagespeed module before 0.10.22.6 for the Apache HTTP Server does n |
| 4.9 | Media | 91% |  | CVE-2021-28652 | An issue was discovered in Squid before 4.15 and 5.x before 5.0.6. Due to i |
| 4.8 | Media | 44% |  | CVE-2026-33006 | A timing attack against mod_auth_digest in Apache HTTP Server 2.4.66 allows |
| 4.7 | Media | 82% |  | CVE-2021-32786 | mod_auth_openidc is an authentication/authorization module for the Apache 2 |
| 4.5 | Media | 27% |  | CVE-2019-12522 | An issue was discovered in Squid through 4.7. When Squid is run as root, it |
| 4.3 | Media | 90% |  | CVE-2016-8612 | Apache HTTP Server mod_cluster before version httpd 2.4.23 is vulnerable to |
| 4.3 | Media | 85% |  | CVE-2025-23419 | When multiple server blocks are configured to share the same IP address and |
| 4.3 | Media | 85% |  | CVE-2011-1176 | The configuration merger in itk.c in the Steinar H. Gunderson mpm-itk Multi |
| 4.3 | Media | 82% |  | CVE-2013-0942 | Cross-site scripting (XSS) vulnerability in EMC RSA Authentication Agent 7. |
| 4.3 | Media | 64% |  | CVE-2012-4360 | Cross-site scripting (XSS) vulnerability in the mod_pagespeed module 0.10.1 |
| 3.7 | Baja | 97% |  | CVE-2016-4053 | Squid 3.x before 3.5.17 and 4.x before 4.0.9 allow remote attackers to obta |
| 3.7 | Baja | 96% |  | CVE-2021-28116 | Squid through 4.14 and 5.x through 5.0.5, in some configurations, allows in |
| 3.1 | Baja | 72% |  | CVE-2021-32792 | mod_auth_openidc is an authentication/authorization module for the Apache 2 |
| 2.6 | Baja | 98% |  | CVE-2009-0796 | Cross-site scripting (XSS) vulnerability in Status.pm in Apache::Status and |
| 2.1 | Baja | 67% |  | CVE-2013-0941 | EMC RSA Authentication API before 8.1 SP1, RSA Web Agent before 5.3.5 for A |
| 0 | Baja | 0% |  | CVE-2025-59362 | (sin datos) |
