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

  def get_port
    begin
      # Start high to better avoid common services
      port = rand(10000..65535)
      s = TCPServer.new("127.0.0.1", port)
      s.close
      return port
    rescue Errno::EADDRINUSE
      retry
    end
  end

  let(:port) { get_port }

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
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
        }
      }
    CONFIG

    host = 'localhost'
    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new(host, port) }
      event_count.times do |i|
        # unicode smiley for testing unicode support!
        socket.puts("#{i} ☹")
        socket.flush
      end
      socket.close

      event_count.times.collect {queue.pop}
    end

    insist { events.length } == event_count
    events = events.sort_by {|e| e.get("message")} # the ordering of events in the queue is highly timing-dependent
    event_count.times do |i|
      event = events[i]
      insist { event.get("message") } == "#{i} ☹"
      insist { ["localhost","ip6-localhost"].includes? event.get("host") }
      insist { event.get("[@metadata][ip_address]") } == '127.0.0.1'
    end
  end

  it "should handle PROXY protocol v1 connections" do
    event_count = 10
    conf = <<-CONFIG
      input {
        tcp {
          proxy_protocol => true
          port => '#{port}'
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
    events = events.sort_by {|e| e.get("message")} # the ordering of events in the queue is highly timing-dependent
    event_count.times do |i|
      insist { events[i].get("message") } == "#{i} ☹"
      insist { events[i].get("host") } == "1.2.3.4"
      insist { events[i].get("port") } == "1234"
      insist { events[i].get("proxy_host") } == "5.6.7.8"
      insist { events[i].get("proxy_port") } == "5678"
    end
  end

  it "should read events with plain codec and ISO-8859-1 charset" do
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

    events = events.sort_by {|e| e.get("idx")} # the ordering of events in the queue is highly timing-dependent
    events.each_with_index do |event, idx|
      insist { event.get("hello") } == data["hello"]
      insist { event.get("foo").to_a } == data["foo"] # to_a to cast Java ArrayList produced by JrJackson
      insist { event.get("baz") } == data["baz"]
      insist { event.get("idx") } == idx + 1
    end # do
  end # describe

  it "should one message per connection" do
    event_count = 10
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

  it "should flush codec after client disconnects" do
    # verifies fix for https://github.com/logstash-plugins/logstash-input-tcp/issues/90
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
          codec => multiline {
              pattern => "^\s"
              what => "previous"
          }
        }
      }
    CONFIG

    data = "a\n 1\n 2\nb\n 1"
    event_count = 2

    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      socket.puts(data)
      socket.close

      # If the codec is not properly flushed, there will be only one event and the second call to queue.pop
      # will block indefinitely. Wrapping this with a timeout ensures that failure mode does not hang the
      # test.
      Timeout.timeout(5) do
        event_count.times.collect do
          queue.pop
        end
      end
    end

    expect(events.length).to equal(event_count)
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
        let(:self_signed_cert) { helper.certificate }
        let(:certificate) { self_signed_cert.first }
        let(:key) { self_signed_cert.last }
        let(:queue) { Queue.new }

        let(:config) do
          {
            "host" => "127.0.0.1",
            "port" => port,
            "ssl_enable" => true,
            "ssl_cert" => certificate,
            "ssl_key" => key,
            "ssl_certificate_authorities" => certificate
          }
        end

        subject(:input) { LogStash::Plugin.lookup("input", "tcp").new(config) }

        before do
          subject.register
        end

        context "when using a certificate chain" do
          let(:chain_of_certificates) { helper.chain_of_certificates }
          let(:config) do
            {
              "host" => "127.0.0.1",
              "port" => port,
              "ssl_enable" => true,
              "ssl_cert" => chain_of_certificates[:b_cert].path,
              "ssl_key" => chain_of_certificates[:b_key].path,
              "ssl_extra_chain_certs" => [ chain_of_certificates[:a_cert].path ],
              "ssl_certificate_authorities" => [ chain_of_certificates[:root_ca].path ],
              "ssl_verify" => true
            }
          end
          let(:tcp) { TCPSocket.new("127.0.0.1", port) }
          let(:sslcontext) do
            sslcontext = OpenSSL::SSL::SSLContext.new
            sslcontext.verify_mode = OpenSSL::SSL::VERIFY_PEER
            sslcontext.ca_file = chain_of_certificates[:root_ca].path
            sslcontext.cert = OpenSSL::X509::Certificate.new(File.read(chain_of_certificates[:aa_cert].path))
            sslcontext.key = OpenSSL::PKey::RSA.new(File.read(chain_of_certificates[:aa_key].path))
            sslcontext
          end
          let(:sslsocket) { OpenSSL::SSL::SSLSocket.new(tcp, sslcontext) }
          let(:input_task) { Stud::Task.new { input.run(queue) } }

          before do
            input_task
          end

          it "should be able to connect and write data" do
            sslsocket.connect
            sslsocket.write("Hello world\n")
            tcp.flush
            sslsocket.close
            tcp.close
            result = input_task.thread.join(0.5)
            expect(result).to be_nil
            expect(queue.size).to eq(1)
          end

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

          describe "an error occurs during an accept" do
            let(:socket) { double("socket").as_null_object }

            before do
              allow(input).to receive(:server_socket).and_return(socket)

              allow(socket).to receive(:accept) do |a1, a2, a3|
                raise StandardError, "blah"
              end
            end

            it "should log the error on accept" do
              allow(input.logger).to receive(:error).with(any_args)
              
              stop = Thread.new {
                sleep 2
                input.do_stop
              }
              expect do
                input.run(Queue.new)
              end.not_to raise_error

              expect(input.logger).to have_received(:error).with(
                ::LogStash::Inputs::Tcp::RUN_LOOP_ERROR_MESSAGE,
                :message => "blah",
                :class => "StandardError",
                :backtrace => anything
              ).at_least(:once)

              stop.join
              # Wait for stop to actually happen
              sleep 1
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
