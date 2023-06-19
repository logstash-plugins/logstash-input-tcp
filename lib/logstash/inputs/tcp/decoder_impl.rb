# encoding: utf-8
require 'java'

class LogStash::Inputs::Tcp::DecoderImpl

  include org.logstash.tcp.Decoder

  def initialize(codec, tcp)
    @tcp = tcp
    @codec = codec
    @first_read = true
  end

  def decode(ctx, data)
    channel = ctx.channel()
    bytes = Java::byte[data.readableBytes].new
    data.getBytes(0, bytes)
    data.release
    tbuf = String.from_java_bytes bytes, "ASCII-8BIT"
    if @first_read
      tbuf = init_first_read(channel, tbuf)
    end
    @tcp.decode_buffer(@ip_address, @address, @port, @codec,
                         @proxy_address, @proxy_port, tbuf, @sslsubject)
  end

  def copy
    self.class.new(@codec.clone, @tcp)
  end

  def flush
    @tcp.flush_codec(@codec, @ip_address, @address, @port, @sslsubject)
  end

  private
  def init_first_read(channel, received)
    channel_addr = channel.remoteAddress()
    if @tcp.proxy_protocol
      pp_hdr, filtered = received.split("\r\n", 2)
      pp_info = pp_hdr.split(/\s/)
      # PROXY proto clientip proxyip clientport proxyport
      if pp_info[0] != "PROXY"
        @tcp.logger.error("Invalid proxy protocol header label", :header => pp_hdr)
        raise IOError.new("Invalid proxy protocol header label #{pp_hdr.inspect}")
      else
        @proxy_address = pp_info[3] # layer 3 destination address (proxy's receiving address)
        @proxy_port = pp_info[5] # TCP destination port (proxy's receiving port)
        @ip_address = pp_info[2] # layer 3 source address (outgoing ip of sender)
        @address = extract_host_name(@ip_address)
        @port = pp_info[4] # TCP source port (outgoing port on sender [probably random])
      end
    else
      filtered = received
      @ip_address = channel_addr.get_address.get_host_address # ip address of sender
      @address = extract_host_name(channel_addr) # name _or_ address of sender
      @port = channel_addr.get_port # outgoing port of sender (probably random)
    end
    @sslsubject = extract_sslsubject(channel)
    @first_read = false
    filtered
  end

  private
  def extract_sslsubject(channel)
    return nil unless @tcp.ssl_peer_verification_enabled?

    channel.pipeline().get("ssl-handler").engine().getSession().getPeerPrincipal().getName()
  rescue Exception => e
    nil
  end

  private
  def extract_host_name(channel_addr)
    channel_addr = java.net.InetSocketAddress.new(channel_addr, 0) if channel_addr.kind_of?(String)

    return channel_addr.get_host_string unless @tcp.dns_reverse_lookup_enabled?

    channel_addr.get_host_name
  end
end
