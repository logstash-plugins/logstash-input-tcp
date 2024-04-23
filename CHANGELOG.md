## 6.4.2
  - update netty to 4.1.109 [#220](https://github.com/logstash-plugins/logstash-input-tcp/pull/220)

## 6.4.1
  - update netty to 4.1.100 [#217](https://github.com/logstash-plugins/logstash-input-tcp/pull/217)

## 6.4.0
  - Reviewed and deprecated SSL settings to comply with Logstash's naming convention [#213](https://github.com/logstash-plugins/logstash-input-tcp/pull/213)
    - Deprecated `ssl_enable` in favor of `ssl_enabled`
    - Deprecated `ssl_cert` in favor of `ssl_certificate`
    - Deprecated `ssl_verify` in favor of `ssl_client_authentication` when mode is `server`
    - Deprecated `ssl_verify` in favor of `ssl_verification_mode` when mode is `client`
  - Added SSL configuration validations

## 6.3.5
  - update netty to 4.1.94 and other dependencies [#216](https://github.com/logstash-plugins/logstash-input-tcp/pull/216)

## 6.3.4
  - Fix: reduce error logging (to info level) on connection resets [#214](https://github.com/logstash-plugins/logstash-input-tcp/pull/214)

## 6.3.3
  - bump netty to 4.1.93 [#212](https://github.com/logstash-plugins/logstash-input-tcp/pull/212)

## 6.3.2
  - Update Netty dependency to 4.1.87 [#209](https://github.com/logstash-plugins/logstash-input-tcp/pull/209)

## 6.3.1
  - Fixes a regression in which the ssl_subject was missing for SSL-secured connections in server mode [#199](https://github.com/logstash-plugins/logstash-input-tcp/pull/199)

## 6.3.0
  - Feat: ssl_supported_protocols (TLSv1.3) + ssl_cipher_suites [#198](https://github.com/logstash-plugins/logstash-input-tcp/pull/198)

## 6.2.7
  - Build: skip shadowing jar dependencies [#187](https://github.com/logstash-plugins/logstash-input-tcp/pull/187)
    * plugin no longer shadows dependencies into its *logstash-input-tcp.jar*
    * log4j-api is now a provided dependency and is no longer packaged with the plugin

## 6.2.6
  - [DOC] Fix incorrect pipeline code snippet [#194](https://github.com/logstash-plugins/logstash-input-tcp/pull/194)
  - Update log4j dependency to 2.17.1 [#196](https://github.com/logstash-plugins/logstash-input-tcp/pull/196)

## 6.2.5
  - Update log4j dependency to 2.17.0

## 6.2.4
  - Update Log4j dependency to 2.16, ensuring this plugin's runtime relies only on log4j-api instead 
    of providing its own log4j-core. [#188](https://github.com/logstash-plugins/logstash-input-tcp/pull/188)

## 6.2.3
  - Update log4j dependencies [#186](https://github.com/logstash-plugins/logstash-input-tcp/pull/186)

## 6.2.2
  - Internal: update to Gradle 7 [#184](https://github.com/logstash-plugins/logstash-input-tcp/pull/184)
  - Internal: relax jruby-openssl upper bound [#185](https://github.com/logstash-plugins/logstash-input-tcp/pull/185)

## 6.2.1
  - Fix: restore logic to add the Bouncy-Castle security provider at runtime [#181](https://github.com/logstash-plugins/logstash-input-tcp/pull/181)
    - required to properly read encrypted (legacy) OpenSSL PKCS#5v1.5 keys

## 6.2.0
 - Added ECS Compatibility Mode [#165](https://github.com/logstash-plugins/logstash-input-tcp/pull/165)
   - When operating in an ECS Compatibility mode, metadata about the connection on which we are receiving data is nested in well-named fields under `[@metadata][input][tcp]` instead of at the root level.
 - Fix: source address is no longer missing when a proxy is present

## 6.1.1
 - Changed jar dependencies to reflect newer versions [#179](https://github.com/logstash-plugins/logstash-input-http/pull/179)

## 6.1.0
  - Feat: improve SSL error logging/unwrapping [#178](https://github.com/logstash-plugins/logstash-input-tcp/pull/178)
  - Fix: the plugin will no longer have a side effect of adding the Bouncy-Castle security provider at runtime  

## 6.0.10
  - bumping dependency commons-io [#174](https://github.com/logstash-plugins/logstash-input-tcp/pull/174)

## 6.0.9
  - [DOC] Reorder options alphabetically [#171](https://github.com/logstash-plugins/logstash-input-tcp/pull/171)

## 6.0.8
  - [DOC] better description for `tcp_keep_alive` option [#169](https://github.com/logstash-plugins/logstash-input-tcp/pull/169)

## 6.0.7
  - Fix: reduce error logging (to info level) on connection resets [#168](https://github.com/logstash-plugins/logstash-input-tcp/pull/168)
  - Refactor: only patch Socket classes once (on first input)
  - Refactor: use a proper log4j logger (in Java to avoid surprises when unwrapping `LogStash::Logging::Logger`)

## 6.0.6
  - Updated Netty dependencies. Additionally, this release removes the dependency on `tcnative` +
    `boringssl`, using JVM supplied ciphers instead. This may result in fewer ciphers being available if the JCE
    unlimited strength jurisdiction policy is not installed. (This policy is installed by default on versions of the
    JDK from u161 onwards)[#157](https://github.com/logstash-plugins/logstash-input-tcp/pull/157)

## 6.0.5
  - Fix potential startup crash that could occur when multiple instances of this plugin were started simultaneously [#155](https://github.com/logstash-plugins/logstash-input-tcp/pull/155)

## 6.0.4
  - Refactor: scope java_import to avoid polluting [#152](https://github.com/logstash-plugins/logstash-input-tcp/pull/152)

## 6.0.3
  - Skip empty lines while reading certificate files [#144](https://github.com/logstash-plugins/logstash-input-tcp/issues/144)

## 6.0.2
  - Fixed race condition where data would be accepted before queue was configured

## 6.0.1
  - Support multiple certificates per file [#140](https://github.com/logstash-plugins/logstash-input-tcp/pull/140)

## 6.0.0
  - Removed obsolete `data_timeout` and `ssl_cacert` options

## 5.2.0
  - Added support for pkcs1 and pkcs8 key formats [#122](https://github.com/logstash-plugins/logstash-input-tcp/issues/122)
  - Changed server-mode SSL to run on top of Netty [#122](https://github.com/logstash-plugins/logstash-input-tcp/issues/122)
  - Changed travis testing infra to use logstash tarballs [#122](https://github.com/logstash-plugins/logstash-input-tcp/issues/122)
  - Fixed certificate chain handling and validation [#124](https://github.com/logstash-plugins/logstash-input-tcp/issues/124)

## 5.1.0
 - Added new configuration option `dns_reverse_lookup_enabled` to allow users to disable costly DNS reverse lookups [#100](https://github.com/logstash-plugins/logstash-input-tcp/issues/100)

## 5.0.9
  - New configuration option to set TCP keep-alive [#16](https://github.com/logstash-plugins/logstash-input-tcp/pull/116)

## 5.0.8
  - Reorder shut down of the two event loops to prevent RejectedExecutionException

## 5.0.7
  - Fix broken 5.0.6 release

## 5.0.6
  - Docs: Set the default_codec doc attribute.

## 5.0.5
  - Restore SSLSUBJECT field when ssl_verify is enabled. #115

## 5.0.4
  - Update Netty/tc-native versions to match those in beats input #113

## 5.0.3
  - Fix bug where codec was not flushed when client disconnected
  - Restore INFO logging statement on startup
  - Fixed typo in @metadata tag
  - Update gemspec summary

## 5.0.2
  - Fix bug where this input would crash logstash during some socket reads when acting as an SSL server

## 5.0.1
  - Fix some documentation issues

## 5.0.0
  - Changed the behaviour of the `host` field to contain the resolved peer hostname for a connection instead of its peer IP
  - Mark deprecated :data_timeout and :ssl_cacert options as obsolete
  and moved the peer's IP to the new field `ip_address`

## 4.2.2
  - Fixed regression causing incoming connection host ips being accidentally resolved to hostnames
  - Implemented plain socket server in a non-blocking way improving performance and fixing issues for use cases with a large number of concurrent connections

## 4.2.1
  - Version yanked from RubyGems for accidental behaviour change causing unwanted reverse lookups on connections

## 4.2.0
  - Version yanked from RubyGems for packaging issues

## 4.1.2
  - Add documentation for how to use tcp input to accept log4j2 data.

## 4.1.0
  - Add support for proxy protocol

## 4.0.3
  - Relax constraint on logstash-core-plugin-api to >= 1.60 <= 2.99

## 4.0.2
 - Change the log level of the SSLError for the handshake from **error** to **debug** https://github.com/logstash-plugins/logstash-input-tcp/pull/53
## 4.0.1
 - Republish all the gems under jruby.
## 4.0.0
 - Update the plugin to the version 2.0 of the plugin api, this change is required for Logstash 5.0 compatibility. See https://github.com/elastic/logstash/issues/5141
# 3.0.5
 - Fixed a bug where using a certificate with a passphrase wouldn't work.
# 3.0.4
 - Depend on logstash-core-plugin-api instead of logstash-core, removing the need to mass update plugins on major releases of logstash
# 3.0.3
 - New dependency requirements for logstash-core for the 5.0 release
## 3.0.2
 - Fixed a bug where previous connection would accidentally be closed when accepting new socket connection
 - Fixed an issue with log message which used a closed socket's peer address

## 3.0.1
 - properly convert sslsubject to string before assigning to event field, added specs, see https://github.com/logstash-plugins/logstash-input-tcp/pull/38

## 3.0.0
 - Deprecate ssl_cacert as it's confusing, does it job but when willing to add a chain of certificated the name and behaviour is a bit confusing.
 - Add ssl_extra_chain_certs that allows you to specify a list of certificates path that will be added to the CAStore.
 - Make ssl_verify=true as a default value, if using ssl and performing validation is not reasonable as security might be compromised.
 - Add tests to verify behaviour under different SSL connection circumstances.
 - Fixes #3 and #9.

## 2.1.0
 - Added the receiving port in the event payload, fixes #4

## 2.0.5
 - Fixed malformed SSL crashing Logstash, see https://github.com/logstash-plugins/logstash-input-tcp/pull/25

## 2.0.4
 - Dependency on logstash-core update to >= 2.0.0.beta2 < 3.0.0

## 2.0.3
 - removed usage of RSpec.configure, see https://github.com/logstash-plugins/logstash-input-tcp/pull/21

## 2.0.2
 - refactored & cleaned up plugin structure, see https://github.com/logstash-plugins/logstash-input-tcp/pull/18

## 2.0.0
 - Plugins were updated to follow the new shutdown semantic, this mainly allows Logstash to instruct input plugins to terminate gracefully,
   instead of using Thread.raise on the plugins' threads. Ref: https://github.com/elastic/logstash/pull/3895
 - Dependency on logstash-core update to 2.0
