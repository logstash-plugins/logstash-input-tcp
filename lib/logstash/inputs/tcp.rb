# encoding: utf-8
require "logstash/inputs/base"
require "logstash/util/socket_peer"

# Read events over a TCP socket.
#
# Like stdin and file inputs, each event is assumed to be one line of text.
#
# Can either accept connections from clients or connect to a server,
# depending on `mode`.
class LogStash::Inputs::Tcp < LogStash::Inputs::Base
  config_name "tcp"

  default :codec, "line"

  # When mode is `server`, the address to listen on.
  # When mode is `client`, the address to connect to.
  config :host, :validate => :string, :default => "0.0.0.0"

  # When mode is `server`, the port to listen on.
  # When mode is `client`, the port to connect to.
  config :port, :validate => :number, :required => true

  config :data_timeout, :validate => :number, :default => -1, :deprecated => "This setting is not used by this plugin. It will be removed soon."

  # Mode to operate in. `server` listens for client connections,
  # `client` connects to a server.
  config :mode, :validate => ["server", "client"], :default => "server"

  # Enable SSL (must be set for other `ssl_` options to take effect).
  config :ssl_enable, :validate => :boolean, :default => false

  # Verify the identity of the other end of the SSL connection against the CA.
  # For input, sets the field `sslsubject` to that of the client certificate.
  config :ssl_verify, :validate => :boolean, :default => false

  # The SSL CA certificate, chainfile or CA path. The system CA path is automatically included.
  config :ssl_cacert, :validate => :path

  # SSL certificate path
  config :ssl_cert, :validate => :path

  # SSL key path
  config :ssl_key, :validate => :path

  # SSL key passphrase
  config :ssl_key_passphrase, :validate => :password, :default => nil

  def initialize(*args)
    super(*args)

    # threadsafe socket bookkeeping
    @server_socket = nil
    @client_socket = nil
    @connection_sockets = {}
    @socket_mutex = Mutex.new
  end

  def register
    require "socket"
    require "timeout"
    require "openssl"

    # monkey patch TCPSocket and SSLSocket to include socket peer
    TCPSocket.module_eval{include ::LogStash::Util::SocketPeer}
    OpenSSL::SSL::SSLSocket.module_eval{include ::LogStash::Util::SocketPeer}

    fix_streaming_codecs

    if @ssl_enable
      @ssl_context = OpenSSL::SSL::SSLContext.new
      @ssl_context.cert = OpenSSL::X509::Certificate.new(File.read(@ssl_cert))
      raw_cert = File.read(@ssl_cert)
      
      # Parse chain certificates from @ssl_cert
      certPosition = [0]
      while certPosition[-1]
        certPosition.push(raw_cert.index("-----B", certPosition[-1] + 1))
      end
      
      # Gather chain from certificate
      if certPosition.length > 2
      @ssl_context.extra_chain_cert = Array.new
        for i in 1..(certPosition.length - 2)
          if certPosition[i+1]
            certEnd = certPosition[i+1] - 1
          else
            certEnd = raw_cert.length - 1
          end
          certLink = OpenSSL::X509::Certificate.new(raw_cert[certPosition[i]..certEnd])
          @ssl_context.extra_chain_cert.push(certLink)
        end
      end
      
      @ssl_context.key = OpenSSL::PKey::RSA.new(File.read(@ssl_key),@ssl_key_passphrase)
      if @ssl_verify
        @cert_store = OpenSSL::X509::Store.new
        # Load the system default certificate path to the store
        @cert_store.set_default_paths
        if File.directory?(@ssl_cacert)
          @cert_store.add_path(@ssl_cacert)
        else
          @cert_store.add_file(@ssl_cacert)
        end
        @ssl_context.cert_store = @cert_store
        @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER|OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
      end
    end

    # note that since we are opening a socket in register, we must also make sure we close it
    # in the close method even if we also close it in the stop method since we could have
    # a situation where register is called but not run & stop.

    if server?
      @logger.info("Starting tcp input listener", :address => "#{@host}:#{@port}")
      begin
        set_server_socket(TCPServer.new(@host, @port))
      rescue Errno::EADDRINUSE
        @logger.error("Could not start TCP server: Address in use", :host => @host, :port => @port)
        raise
      end

      set_server_socket(OpenSSL::SSL::SSLServer.new(server_socket, @ssl_context)) if @ssl_enable
    end
  end

  def run(output_queue)
    if server?
      run_server(output_queue)
    else
      run_client(output_queue)
    end
  end

  def stop
    # force close all sockets which will escape any blocking read with a IO exception
    # and any thread using them will exit.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
    client_socket.close rescue nil
    connection_sockets.each{|socket| socket.close rescue nil}
  end

  def close
    # see related comment in register: we must make sure to close the server socket here
    # because it is created in the register method and we could be in the context of having
    # register called but never run & stop, only close.
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
  end

  private

  def run_server(output_queue)
    while !stop?
      begin
        socket = add_connection_socket(server_socket.accept)
        # start a new thread for each connection.
        server_connection_thread(output_queue, socket)
      rescue OpenSSL::SSL::SSLError => e
        @logger.error("SSL Error", :exception => e, :backtrace => e.backtrace)
      rescue
        # if this exception occured while the plugin is stopping
        # just ignore and exit
        raise unless stop?
      end
    end
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    server_socket.close rescue nil
  end

  def run_client(output_queue)
    while !stop?
      set_client_socket(TCPSocket.new(@host, @port))

      if @ssl_enable
        set_client_socket(OpenSSL::SSL::SSLSocket.new(client_socket, @ssl_context))
        begin
          client_socket.connect
        rescue OpenSSL::SSL::SSLError => e
          @logger.error("SSL Error", :exception => e, :backtrace => e.backtrace)
          sleep(1) # prevent hammering peer
          next
        rescue
          # if this exception occured while the plugin is stopping
          # just ignore and exit
          raise unless stop?
        end
      end

      @logger.debug? && @logger.debug("Opened connection", :client => "#{client_socket.peer}")
      handle_socket(client_socket, client_socket.peeraddr[3], output_queue, @codec.clone)
    end
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    client_socket.close rescue nil
  end

  def server_connection_thread(output_queue, socket)
    Thread.new(output_queue, socket) do |q, s|
      begin
        @logger.debug? && @logger.debug("Accepted connection", :client => s.peer, :server => "#{@host}:#{@port}")
        handle_socket(s, s.peeraddr[3], q, @codec.clone)
      ensure
        delete_connection_socket(s)
      end
    end
  end

  def handle_socket(socket, client_address, output_queue, codec)
    while !stop?
      codec.decode(read(socket)) do |event|
        event["host"] ||= client_address
        event["sslsubject"] ||= socket.peer_cert.subject if @ssl_enable && @ssl_verify
        decorate(event)
        output_queue << event
      end
    end
  rescue EOFError
    @logger.debug? && @logger.debug("Connection closed", :client => socket.peer)
  rescue Errno::ECONNRESET
    @logger.debug? && @logger.debug("Connection reset by peer", :client => socket.peer)
  rescue => e
    # if plugin is stopping, don't bother logging it as an error
    @logger.error("An error occurred. Closing connection", :client => socket.peer, :exception => e, :backtrace => e.backtrace) unless stop?
  ensure
    # catch all rescue nil on close to discard any close errors or invalid socket
    socket.close rescue nil

    codec.respond_to?(:flush) && codec.flush do |event|
      event["host"] ||= client_address
      event["sslsubject"] ||= socket.peer_cert.subject if @ssl_enable && @ssl_verify
      decorate(event)
      output_queue << event
    end
  end

  def server?
    @mode == "server"
  end

  def read(socket)
    socket.sysread(16384)
  end

  # threadsafe sockets bookkeeping

  def set_client_socket(socket)
    @socket_mutex.synchronize{@client_socket = socket}
  end

  def client_socket
    @socket_mutex.synchronize{@client_socket}
  end

  def set_server_socket(socket)
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
end
