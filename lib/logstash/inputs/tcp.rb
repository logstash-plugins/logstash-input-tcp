# encoding: utf-8

require "java"

require "logstash/inputs/base"
require "logstash/util/socket_peer"
require "logstash-input-tcp_jars"
require 'logstash/plugin_mixins/ecs_compatibility_support'
require "logstash/plugin_mixins/normalize_config_support"

require "socket"
require "openssl"

# Read events over a TCP socket.
#
# Like stdin and file inputs, each event is assumed to be one line of text.
#
# Can either accept connections from clients or connect to a server,
# depending on `mode`.
#
# #### Accepting log4j2 logs
#
# Log4j2 can send JSON over a socket, and we can use that combined with our tcp
# input to accept the logs.
#
# First, we need to configure your application to send logs in JSON over a
# socket. The following log4j2.xml accomplishes this task.
#
# Note, you will want to change the `host` and `port` settings in this
# configuration to match your needs.
#
#     <Configuration>
#       <Appenders>
#          <Socket name="Socket" host="localhost" port="12345">
#            <JsonLayout compact="true" eventEol="true" />
#         </Socket>
#       </Appenders>
#       <Loggers>
#         <Root level="info">
#           <AppenderRef ref="Socket"/>
#         </Root>
#       </Loggers>
#     </Configuration>
#
# To accept this in Logstash, you will want tcp input and a date filter:
#
#     input {
#       tcp {
#         port => 12345
#         codec => json
#       }
#     }
#
# and add a date filter to take log4j2's `timeMillis` field and use it as the
# event timestamp
#
#     filter {
#       date {
#         match => [ "timeMillis", "UNIX_MS" ]
#       }
#     }
class LogStash::Inputs::Tcp < LogStash::Inputs::Base

  java_import 'org.logstash.tcp.InputLoop'
  java_import 'org.logstash.tcp.SslContextBuilder'

  require_relative "tcp/decoder_impl"

  # ecs_compatibility option, provided by Logstash core or the support adapter.
  include LogStash::PluginMixins::ECSCompatibilitySupport(:disabled, :v1, :v8 => :v1)

  include LogStash::PluginMixins::NormalizeConfigSupport

  config_name "tcp"

  default :codec, "line"

  # When mode is `server`, the address to listen on.
  # When mode is `client`, the address to connect to.
  config :host, :validate => :string, :default => "0.0.0.0"

  # When mode is `server`, the port to listen on.
  # When mode is `client`, the port to connect to.
  config :port, :validate => :number, :required => true

  # Mode to operate in. `server` listens for client connections,
  # `client` connects to a server.
  config :mode, :validate => ["server", "client"], :default => "server"

  # Proxy protocol support, only v1 is supported at this time
  # http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt
  config :proxy_protocol, :validate => :boolean, :default => false

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enable, :validate => :boolean, :default => false, :deprecated => "Use 'ssl_enabled' instead."

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enabled, :validate => :boolean, :default => false

  # Controls the server’s behavior in regard to requesting a certificate from client connections.
  # `none`: No client authentication
  # `optional`: Requests a client certificate but the client is not required to present one.
  # `required`: Forces a client to present a certificate.
  # This option needs to be used with `ssl_certificate_authorities` and a defined list of CAs.
  config :ssl_client_authentication, :validate => %w[none optional required], :default => 'required'

  # Verify the identity of the other end of the SSL connection against the CA.
  # For input, sets the field `sslsubject` to that of the client certificate.
  config :ssl_verify, :validate => :boolean, :default => true, :deprecated => "Use 'ssl_client_authentication' when mode is 'server' or 'ssl_verification_mode' when mode is 'client'"

  # Options to verify the server's certificate.
  # "full": validates that the provided certificate has an issue date that’s within the not_before and not_after dates;
  # chains to a trusted Certificate Authority (CA); has a hostname or IP address that matches the names within the certificate.
  # "certificate": Validates the provided certificate and verifies that it’s signed by a trusted authority (CA), but does’t check the certificate hostname.
  # "none": performs no certificate validation. Disabling this severely compromises security (https://www.cs.utexas.edu/~shmat/shmat_ccs12.pdf)
  config :ssl_verification_mode, :validate => %w[full none], :default => 'full'

  # SSL certificate path
  config :ssl_cert, :validate => :path, :deprecated => "Use 'ssl_certificate' instead."

  # SSL certificate path
  config :ssl_certificate, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  # An Array of extra X509 certificates to be added to the certificate chain.
  # Useful when the CA chain is not necessary in the system store.
  config :ssl_extra_chain_certs, :validate => :array, :default => []

  # Validate client certificates against these authorities. You can define multiple files or paths.
  # All the certificates will be read and added to the trust store.
  config :ssl_certificate_authorities, :validate => :array, :default => []

  # NOTE: the default setting [] uses Java SSL engine defaults.
  config :ssl_supported_protocols, :validate => ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'], :default => [], :list => true

  # The list of ciphers suite to use, listed by priorities.
  # NOTE: the default setting [] uses Java SSL defaults.
  config :ssl_cipher_suites, :validate => SslContextBuilder.getSupportedCipherSuites.to_a, :default => [], :list => true

  # Instruct the socket to use TCP keep alives. Uses OS defaults for keep alive settings.
  config :tcp_keep_alive, :validate => :boolean, :default => false

  # Option to allow users to avoid DNS Reverse Lookup.
  config :dns_reverse_lookup_enabled, :validate => :boolean, :default => true

  # Monkey patch TCPSocket and SSLSocket to include socket peer
  # @private
  def self.patch_socket_peer!
    unless TCPSocket < ::LogStash::Util::SocketPeer
      TCPSocket.send :include, ::LogStash::Util::SocketPeer
    end
    unless OpenSSL::SSL::SSLSocket < ::LogStash::Util::SocketPeer
      OpenSSL::SSL::SSLSocket.send :include, ::LogStash::Util::SocketPeer
    end
  end

  def initialize(*args)
    super(*args)

    setup_fields!
    setup_ssl_params!

    self.class.patch_socket_peer!

    # threadsafe socket bookkeeping
    @server_socket = nil
    @client_socket = nil
    @connection_sockets = {}
    @socket_mutex = Mutex.new

    @ssl_context = nil
  end

  def register
    fix_streaming_codecs
    validate_ssl_config!

    if server?
      @loop = InputLoop.new(@host, @port, DecoderImpl.new(@codec, self), @tcp_keep_alive, java_ssl_context)
    end
  end

  def run(output_queue)
    @output_queue = output_queue
    if server?
      @logger.info("Starting tcp input listener", :address => "#{@host}:#{@port}", :ssl_enabled => @ssl_enabled)
      @loop.run
    else
      run_client()
    end
  end

  def stop
    # force close all sockets which will escape any blocking read with a IO exception
    # and any thread using them will exit.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
    @loop.close rescue nil
    client_socket.close rescue nil
    connection_sockets.each{|socket| socket.close rescue nil}
  end

  def close
    # see related comment in register: we must make sure to close the server socket here
    # because it is created in the register method and we could be in the context of having
    # register called but never run & stop, only close.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
    @loop.close rescue nil
  end

  def decode_buffer(client_ip_address, client_address, client_port, codec, proxy_address,
                    proxy_port, tbuf, ssl_subject)
    codec.decode(tbuf) do |event|
      if @proxy_protocol
        event.set(@field_proxy_host, proxy_address) unless event.get(@field_proxy_host)
        event.set(@field_proxy_port, proxy_port) unless event.get(@field_proxy_port)
      end
      enqueue_decorated(event, client_ip_address, client_address, client_port, ssl_subject)
    end
  end

  def flush_codec(codec, client_ip_address, client_address, client_port, ssl_subject)
    codec.flush do |event|
      enqueue_decorated(event, client_ip_address, client_address, client_port, ssl_subject)
    end
  end

  def dns_reverse_lookup_enabled?
    @dns_reverse_lookup_enabled
  end

  def ssl_peer_verification_enabled?
    return false unless @ssl_enabled
    if server?
      @ssl_client_authentication && @ssl_client_authentication != 'none'
    else
      @ssl_verification_mode == 'full'
    end
  end

  private

  def run_client()
    while !stop?
      self.client_socket = new_client_socket
      handle_socket(client_socket)
    end
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    client_socket.close rescue nil
  end

  # only called in client mode
  def handle_socket(socket)
    client_address = socket.peeraddr[3]
    client_ip_address = socket.peeraddr[2]
    client_port = socket.peeraddr[1]

    # Client mode sslsubject extraction, server mode happens in DecoderImpl#decode
    ssl_subject = socket.peer_cert.subject.to_s if ssl_peer_verification_enabled?
    peer = "#{client_address}:#{client_port}"
    first_read = true
    codec = @codec.clone
    while !stop?
      tbuf = socket.sysread(16384)
      if @proxy_protocol && first_read
        first_read = false
        pp_hdr, tbuf = tbuf.split("\r\n", 2)

        pp_info = pp_hdr.split(/\s/)
        # PROXY proto clientip proxyip clientport proxyport
        if pp_info[0] != "PROXY"
          @logger.error("invalid proxy protocol header label", :hdr => pp_hdr)
          raise IOError
        else
          proxy_address = pp_info[3]
          proxy_port = pp_info[5]
          client_address = pp_info[2]
          client_port = pp_info[4]
          client_ip_address = ''
        end
      end
      decode_buffer(client_ip_address, client_address, client_port, codec, proxy_address,
                    proxy_port, tbuf, ssl_subject)
    end
  rescue EOFError
    @logger.debug? && @logger.debug("Connection closed", :client => peer)
  rescue Errno::ECONNRESET
    @logger.debug? && @logger.debug("Connection reset by peer", :client => peer)
  rescue OpenSSL::SSL::SSLError => e
    @logger.error("SSL error", :client => peer, :message => e.message, :exception => e.class, :backtrace => e.backtrace)
  rescue => e
    # if plugin is stopping, don't bother logging it as an error
    !stop? && @logger.error("An error occurred, closing connection", :client => peer, :message => e.message, :exception => e.class, :backtrace => e.backtrace)
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    socket.close rescue nil
    flush_codec(codec, client_ip_address, client_address, client_port, ssl_subject)
  end

  def enqueue_decorated(event, client_ip_address, client_address, client_port, ssl_subject)
    event.set(@field_host, client_address) unless event.get(@field_host)
    event.set(@field_host_ip, client_ip_address) unless event.get(@field_host_ip)
    event.set(@field_port, client_port) unless event.get(@field_port)
    event.set(@field_sslsubject, ssl_subject) unless ssl_subject.nil? || event.get(@field_sslsubject)
    decorate(event)
    @output_queue << event
  end

  # setup the field names, with respect to ECS compatibility.
  def setup_fields!
    @field_host       = ecs_select[disabled: "host",                    v1: "[@metadata][input][tcp][source][name]"        ].freeze
    @field_host_ip    = ecs_select[disabled: "[@metadata][ip_address]", v1: "[@metadata][input][tcp][source][ip]"          ].freeze
    @field_port       = ecs_select[disabled: "port",                    v1: "[@metadata][input][tcp][source][port]"        ].freeze
    @field_proxy_host = ecs_select[disabled: "proxy_host",              v1: "[@metadata][input][tcp][proxy][ip]"           ].freeze
    @field_proxy_port = ecs_select[disabled: "proxy_port",              v1: "[@metadata][input][tcp][proxy][port]"         ].freeze
    @field_sslsubject = ecs_select[disabled: "sslsubject",              v1: "[@metadata][input][tcp][tls][client][subject]"].freeze
  end

  def validate_ssl_config!
    unless @ssl_enabled
      ignored_ssl_settings = original_params.select { |k| k != 'ssl_enabled' && k != 'ssl_enable' && k.start_with?('ssl_') }
      @logger.warn("Configured SSL settings are not used when `#{provided_ssl_enabled_config_name}` is set to `false`: #{ignored_ssl_settings.keys}") if ignored_ssl_settings.any?
      return
    end

    if @ssl_certificate && !@ssl_key
      raise LogStash::ConfigurationError, "Using an `ssl_certificate` requires an `ssl_key`"
    elsif @ssl_key && !@ssl_certificate
      raise LogStash::ConfigurationError, 'An `ssl_certificate` is required when using an `ssl_key`'
    end

    if server?
      validate_server_ssl_config!
    else
      validate_client_ssl_config!
    end
  end

  def validate_client_ssl_config!
    if original_params.include?('ssl_client_authentication')
      raise LogStash::ConfigurationError, "`ssl_client_authentication` must not be configured when mode is `client`, use `ssl_verification_mode` instead."
    end
  end

  def validate_server_ssl_config!
    if original_params.include?('ssl_verification_mode')
      raise LogStash::ConfigurationError, "`ssl_verification_mode` must not be configured when mode is `server`, use `ssl_client_authentication` instead."
    end

    if @ssl_certificate.nil?
      raise LogStash::ConfigurationError, "An `ssl_certificate` is required when `#{provided_ssl_enabled_config_name}` => true"
    end

    ssl_client_authentication_provided = original_params.include?('ssl_client_authentication')
    if ssl_client_authentication_provided && @ssl_client_authentication != 'none' && (@ssl_certificate_authorities.nil? || @ssl_certificate_authorities.empty?)
        raise LogStash::ConfigurationError, "An `ssl_certificate_authorities` is required when `ssl_client_authentication` => `#{@ssl_client_authentication}`"
    end
  end

  def provided_ssl_enabled_config_name
    original_params.include?('ssl_enable') ? 'ssl_enable' : 'ssl_enabled'
  end

  def setup_ssl_params!
    @ssl_enabled = normalize_config(:ssl_enabled) do |normalizer|
      normalizer.with_deprecated_alias(:ssl_enable)
    end

    @ssl_certificate = normalize_config(:ssl_certificate) do |normalizer|
      normalizer.with_deprecated_alias(:ssl_cert)
    end

    if server?
      @ssl_client_authentication = normalize_config(:ssl_client_authentication) do |normalizer|
        normalizer.with_deprecated_mapping(:ssl_verify) do |ssl_verify|
          ssl_verify == true ? "required" : "none"
        end
      end
    else
      @ssl_verification_mode = normalize_config(:ssl_verification_mode) do |normalize|
        normalize.with_deprecated_mapping(:ssl_verify) do |ssl_verify|
          ssl_verify == true ? "full" : "none"
        end
      end
    end

    params['ssl_enabled'] = @ssl_enabled unless @ssl_enabled.nil?
    params['ssl_certificate'] = @ssl_certificate unless @ssl_certificate.nil?
    params['ssl_verification_mode'] = @ssl_verification_mode unless @ssl_verification_mode.nil?
    params['ssl_client_authentication'] = @ssl_client_authentication unless @ssl_client_authentication.nil?
  end

  def server?
    @mode == "server"
  end

  def ssl_context
    return @ssl_context if @ssl_context

    begin
      @ssl_context = new_ssl_context
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_certificate))
      @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key),@ssl_key_passphrase.value)
      if @ssl_extra_chain_certs.any?
        @ssl_context.extra_chain_cert = @ssl_extra_chain_certs.map {|cert_path| OpenSSL::X509::Certificate.new(File.read(cert_path)) }
        @ssl_context.extra_chain_cert.unshift(OpenSSL::X509::Certificate.new(File.read(@ssl_certificate)))
      end
      if @ssl_verification_mode == "full"
        @ssl_context.cert_store  = load_cert_store
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      end

      @ssl_context.min_version = :TLS1_1 # not strictly required - JVM should have disabled TLSv1
      if ssl_supported_protocols.any?
        disabled_protocols = ['TLSv1.1', 'TLSv1.2', 'TLSv1.3'] - ssl_supported_protocols
        unless OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3 # work-around JRuby-OpenSSL bug - missing constant
          @ssl_context.max_version = :TLS1_2 if disabled_protocols.delete('TLSv1.3')
        end
        # mapping 'TLSv1.2' -> OpenSSL::SSL::OP_NO_TLSv1_2
        disabled_protocols.map! { |v| OpenSSL::SSL.const_get "OP_NO_#{v.sub('.', '_')}" }
        @ssl_context.options = disabled_protocols.reduce(@ssl_context.options, :|)
      end

      if ssl_cipher_suites.any?
        @ssl_context.ciphers = ssl_cipher_suites # Java cipher names work with JOSSL >= 0.12.2
      end
    rescue => e
      @logger.error("Could not inititalize SSL context", :message => e.message, :exception => e.class, :backtrace => e.backtrace)
      raise e
    end

    @ssl_context
  end

  # @note to be able to hook up into #ssl_context from tests
  def new_ssl_context
    OpenSSL::SSL::SSLContext.new
  end

  def load_cert_store
    cert_store = OpenSSL::X509::Store.new
    cert_store.set_default_paths
    @ssl_certificate_authorities.each do |cert|
      cert_store.add_file(cert)
    end
    cert_store
  end

  def new_client_socket
    socket = TCPSocket.new(@host, @port)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, @tcp_keep_alive)

    if @ssl_enabled
      socket = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
      socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, @tcp_keep_alive)
      socket.connect
    end

    @logger.debug? && @logger.debug("Opened connection", :client => "#{socket.peer}")

    socket
  rescue OpenSSL::SSL::SSLError => e
    @logger.error("SSL Error", :message => e.message, :exception => e.class, :backtrace => e.backtrace)
    # catch all rescue nil on close to discard any close errors or invalid socket
    socket.close rescue nil
    sleep(1) # prevent hammering peer
    retry
  rescue
    # if this exception occured while the plugin is stopping
    # just ignore and exit
    raise unless stop?
  end

  # threadsafe sockets bookkeeping

  def client_socket=(socket)
    @socket_mutex.synchronize{@client_socket = socket}
  end

  def client_socket
    @socket_mutex.synchronize{@client_socket}
  end

  def server_socket=(socket)
    @socket_mutex.synchronize{@server_socket = socket}
  end

  def server_socket
    @socket_mutex.synchronize{@server_socket}
  end

  def add_connection_socket(socket)
    @socket_mutex.synchronize{@connection_sockets[socket] = true}
    socket
  end

  def delete_connection_socket(socket)
    @socket_mutex.synchronize{@connection_sockets.delete(socket)}
  end

  def connection_sockets
    @socket_mutex.synchronize{@connection_sockets.keys.dup}
  end

  def java_ssl_context
    return nil unless @ssl_enabled
    SslContextBuilder.new(@ssl_certificate, @ssl_key, @ssl_key_passphrase.value)
      .set_client_authentication(SslContextBuilder::SslClientAuthentication.of(@ssl_client_authentication))
      .set_certificate_authorities(@ssl_certificate_authorities.to_java(:string))
      .set_extra_chain_certs(@ssl_extra_chain_certs.to_java(:string))
      .set_supported_protocols(ssl_supported_protocols.to_java(:string))
      .set_cipher_suites(ssl_cipher_suites.to_java(:string))
      .build_context
  rescue java.lang.IllegalArgumentException => e
    @logger.error("SSL configuration invalid", error_details(e))
    raise LogStash::ConfigurationError, e
  rescue java.lang.Exception => e
    @logger.error("SSL configuration failed", error_details(e, true))
    raise e
  end

  def error_details(e, trace = false)
    error_details = { :exception => e.class, :message => e.message }
    error_details[:backtrace] = e.backtrace if trace || @logger.debug?
    cause = e.cause
    if cause && e != cause
      error_details[:cause] = { :exception => cause.class, :message => cause.message }
      error_details[:cause][:backtrace] = cause.backtrace if trace || @logger.debug?
    end
    error_details
  end

end
