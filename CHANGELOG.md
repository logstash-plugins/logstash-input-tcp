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
