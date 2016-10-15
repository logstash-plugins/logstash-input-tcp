# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "socket"
require "timeout"
require "logstash/json"
require "logstash/inputs/tcp"
require "stud/try"
require "stud/task"
require "flores/pki"
require "openssl"

require_relative "../spec_helper"

#Cabin::Channel.get(LogStash).subscribe(STDOUT)
#Cabin::Channel.get(LogStash).level = :debug
describe LogStash::Inputs::Tcp do

  context "codec (PR #1372)" do
    it "switches from plain to line" do
      require "logstash/codecs/plain"
      require "logstash/codecs/line"
      plugin = LogStash::Inputs::Tcp.new("codec" => LogStash::Codecs::Plain.new, "port" => 0)
      plugin.register
      insist { plugin.codec }.is_a?(LogStash::Codecs::Line)
      plugin.close
    end
    it "switches from json to json_lines" do
      require "logstash/codecs/json"
      require "logstash/codecs/json_lines"
      plugin = LogStash::Inputs::Tcp.new("codec" => LogStash::Codecs::JSON.new, "port" => 0)
      plugin.register
      insist { plugin.codec }.is_a?(LogStash::Codecs::JSONLines)
      plugin.close
    end
  end

  it "should read plain with unicode" do
    event_count = 10
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
        }
      }
    CONFIG

    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      event_count.times do |i|
        # unicode smiley for testing unicode support!
        socket.puts("#{i} ☹")
        socket.flush
      end
      socket.close

      event_count.times.collect {queue.pop}
    end

    insist { events.length } == event_count
    event_count.times do |i|
      insist { events[i].get("message") } == "#{i} ☹"
    end
  end

  it "should handle PROXY protocol v1 connections" do
    event_count = 10
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          proxy_protocol => true
        }
      }
    CONFIG

    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      socket.puts("PROXY TCP4 1.2.3.4 5.6.7.8 1234 5678\r");
      socket.flush
      event_count.times do |i|
        # unicode smiley for testing unicode support!
        socket.puts("#{i} ☹")
        socket.flush
      end
      socket.close

      event_count.times.collect {queue.pop}
    end

    insist { events.length } == event_count
    event_count.times do |i|
      insist { events[i].get("message") } == "#{i} ☹"
      insist { events[i].get("host") } == "1.2.3.4"
      insist { events[i].get("port") } == "1234"
      insist { events[i].get("proxy_host") } == "5.6.7.8"
      insist { events[i].get("proxy_port") } == "5678"
    end
  end

  it "should read events with plain codec and ISO-8859-1 charset" do
    port = rand(1024..65535)
    charset = "ISO-8859-1"
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          codec => plain { charset => "#{charset}" }
        }
      }
    CONFIG

    event = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      text = "\xA3" # the £ symbol in ISO-8859-1 aka Latin-1
      text.force_encoding("ISO-8859-1")
      socket.puts(text)
      socket.close

      queue.pop
    end

    # Make sure the 0xA3 latin-1 code converts correctly to UTF-8.
    insist { event.get("message").size } == 1
    insist { event.get("message").bytesize } == 2
    insist { event.get("message") } == "£"
  end

  it "should read events with json codec" do
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          codec => json
        }
      }
    CONFIG

    data = {
      "hello" => "world",
      "foo" => [1,2,3],
      "baz" => { "1" => "2" },
      "host" => "example host"
    }

    event = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      socket.puts(LogStash::Json.dump(data))
      socket.close

      queue.pop
    end

    insist { event.get("hello") } == data["hello"]
    insist { event.get("foo").to_a } == data["foo"] # to_a to cast Java ArrayList produced by JrJackson
    insist { event.get("baz") } == data["baz"]

    # Make sure the tcp input, w/ json codec, uses the event's 'host' value,
    # if present, instead of providing its own
    insist { event.get("host") } == data["host"]
  end

  it "should read events with json codec (testing 'host' handling)" do
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          codec => json
        }
      }
    CONFIG

    data = {
      "hello" => "world"
    }

    event = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      socket.puts(LogStash::Json.dump(data))
      socket.close

      queue.pop
    end

    insist { event.get("hello") } == data["hello"]
    insist { event }.include?("host")
  end

  it "should read events with json_lines codec" do
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          codec => json_lines
        }
      }
    CONFIG

    data = {
      "hello" => "world",
      "foo" => [1,2,3],
      "baz" => { "1" => "2" },
      "idx" => 0
    }
    event_count = 5

    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      (1..event_count).each do |idx|
        data["idx"] = idx
        socket.puts(LogStash::Json.dump(data) + "\n")
      end
      socket.close

      (1..event_count).map{queue.pop}
    end

    events.each_with_index do |event, idx|
      insist { event.get("hello") } == data["hello"]
      insist { event.get("foo").to_a } == data["foo"] # to_a to cast Java ArrayList produced by JrJackson
      insist { event.get("baz") } == data["baz"]
      insist { event.get("idx") } == idx + 1
    end # do
  end # describe

  it "should one message per connection" do
    event_count = 10
    port = rand(1024..65535)
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
        }
      }
    CONFIG

    events = input(conf) do |pipeline, queue|
      event_count.times do |i|
        socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
        socket.puts("#{i}")
        socket.flush
        socket.close
      end

      # since each message is sent on its own tcp connection & thread, exact receiving order cannot be garanteed
      event_count.times.collect{queue.pop}.sort_by{|event| event.get("message")}
    end

    event_count.times do |i|
      insist { events[i].get("message") } == "#{i}"
    end
  end

  # below are new specs added in the context of the shutdown semantic refactor.
  # TODO:
  #   - refactor all specs using this new model
  #   - pipelineless_input has been basically copied from the udp input specs, it should be DRYied up
  #   - see if we should miminc the udp input UDPClient helper class instead of directly using TCPSocket

  describe "LogStash::Inputs::Tcp new specs style" do

    before do
      srand(RSpec.configuration.seed)
    end

    let(:port) { rand(1024..65535) }
    subject { LogStash::Plugin.lookup("input", "tcp").new({ "port" => port }) }
    let!(:helper) { TcpHelpers.new }

    after :each do
      subject.close rescue nil
    end

    describe "#register" do
      it "should register without errors" do
        expect { subject.register }.to_not raise_error
      end
    end

    describe "#receive" do
      shared_examples "receiving events" do
        # TODO(sissel): Implement normal event-receipt tests as as a shared example
      end

      context "when ssl_enable is true" do
        let(:pki) { Flores::PKI.generate }
        let(:certificate) { pki[0] }
        let(:key) { pki[1] }
        let(:certificate_file) { Stud::Temporary.file }
        let(:key_file) { Stud::Temporary.file }
        let(:queue) { Queue.new }

        let(:config) do
          {
            "host" => "127.0.0.1",
            "port" => port,
            "ssl_enable" => true,
            "ssl_cert" => certificate_file.path,
            "ssl_key" => key_file.path,

            # Trust our self-signed cert.
            # TODO(sissel): Make this a separate certificate for the client
            "ssl_extra_chain_certs" => certificate_file.path
          }
        end

        subject(:input) { LogStash::Plugin.lookup("input", "tcp").new(config) }

        before do
          certificate_file.write(certificate)
          key_file.write(key)

          # Close to flush the file writes.
          certificate_file.close
          key_file.close
          subject.register
        end

        after do
          File.unlink(certificate_file.path)
          File.unlink(key_file.path)
        end

        context "with a poorly-behaving client" do
          let!(:input_task) { Stud::Task.new { input.run(queue) } }

          after { input.close }

          context "that disconnects before doing TLS handshake" do
            before do
              client = TCPSocket.new("127.0.0.1", port)
              client.close
            end

            it "should not negatively impact the plugin" do
              # TODO(sissel): Look for a better way to detect this failure
              # besides a sleep/wait.
              result = input_task.thread.join(0.5)
              expect(result).to be_nil
            end
          end

          context "that sends garbage instead of TLS handshake" do
            let!(:input_task) { Stud::Task.new { input.run(queue) } }
            let(:max_length) { 1000 }
            let(:garbage) { Flores::Random.iterations(max_length).collect { Flores::Random.integer(1...255) }.pack("C*") }
            before do
              # Assertion to verify this test is actually sending something.
              expect(garbage.length).to be > 0

              client = TCPSocket.new("127.0.0.1", port)
              client.write(garbage)
              client.flush
              Thread.new { sleep(1); client.close }
            end
            it "should not negatively impact the plugin" do
              # TODO(sissel): Look for a better way to detect this failure besides a sleep/wait.
              result = input_task.thread.join(0.5)
              expect(result).to be_nil
            end
          end

          context "connection was healthy but now has garbage or corruption" do
            let!(:input_task) { Stud::Task.new { input.run(queue) } }
            let(:tcp) { TCPSocket.new("127.0.0.1", port) }
            let(:sslcontext) { OpenSSL::SSL::SSLContext.new }
            let(:sslsocket) { OpenSSL::SSL::SSLSocket.new(tcp, sslcontext) }
            let(:max_length) { 1000 }
            let(:garbage) { Flores::Random.iterations(max_length).collect { Flores::Random.integer(1...255) }.pack("C*") }

            before do
              sslcontext.cert = certificate
              sslcontext.key = key
              sslcontext.verify_mode = OpenSSL::SSL::VERIFY_NONE

              sslsocket.connect
              sslsocket.write("Hello world\n")

              # Assertion to verify this test is actually sending something.
              expect(garbage.length).to be > 0
              tcp.write(garbage)
              tcp.flush
              sslsocket.close
              tcp.close
            end

            it "should not negatively impact the plugin" do
              # TODO(sissel): Look for a better way to detect this failure besides a sleep/wait.
              result = input_task.thread.join(0.5)
              expect(result).to be_nil
            end
          end
        end

        # TODO(sissel): Spec multiple clients where only one is bad.

        context "with client certificate problems" do
          context "using an expired certificate"
          context "using an untrusted certificate"
        end

        context "with a good connection" do
          # TODO(sissel): use shared example
          include_examples "receiving events"
        end

      end
    end

    it_behaves_like "an interruptible input plugin" do
      let(:config) { { "port" => port } }
    end
  end
end
