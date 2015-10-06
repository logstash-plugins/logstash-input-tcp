#!/usr/bin/env ruby

require "socket"
require "openssl"

##
# Send events to SSL to logstash
##

class TCPClient

  attr_reader :id, :port, :socket

  def initialize(port, id)
    @port = port
    @id   = id
  end

  def connect
    return @socket if @socket
    #ssl_context = OpenSSL::SSL::SSLContext.new
    @socket      = TCPSocket.new("127.0.0.1", port)
    #ssl_client  = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
    #@socket     = ssl_client.connect
    @socket
  end

  def send(msg)
    puts "send #{id}:#{msg}"
    socket.puts(msg)
  end
end

port      = 12345
nclients  = 1
clients   = []

nclients.times do |client_id|
  client = TCPClient.new(port, client_id)
  client.connect
  clients << client
end

i = 0
while(true) do
  clients.each do |client|
    client.send "msg #{i}"
  end
  i+=1
end

ssl_client.close rescue nil
