# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "socket"
require "timeout"
require "logstash/json"
require "logstash/inputs/tcp"
require "stud/try"
require "flores/pki"
require "openssl"

require_relative "../spec_helper"

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
    port = 5511
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
      insist { events[i]["message"] } == "#{i} ☹"
    end
  end

  it "should read events with plain codec and ISO-8859-1 charset" do
    port = 5513
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
    insist { event["message"].size } == 1
    insist { event["message"].bytesize } == 2
    insist { event["message"] } == "£"
  end

  it "should read events with json codec" do
    port = 5514
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

    insist { event["hello"] } == data["hello"]
    insist { event["foo"].to_a } == data["foo"] # to_a to cast Java ArrayList produced by JrJackson
    insist { event["baz"] } == data["baz"]

    # Make sure the tcp input, w/ json codec, uses the event's 'host' value,
    # if present, instead of providing its own
    insist { event["host"] } == data["host"]
  end

  it "should read events with json codec (testing 'host' handling)" do
    port = 5514
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

    insist { event["hello"] } == data["hello"]
    insist { event }.include?("host")
  end

  it "should read events with json_lines codec" do
    port = 5515
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
      insist { event["hello"] } == data["hello"]
      insist { event["foo"].to_a } == data["foo"] # to_a to cast Java ArrayList produced by JrJackson
      insist { event["baz"] } == data["baz"]
      insist { event["idx"] } == idx + 1
    end # do
  end # describe

  it "should one message per connection" do
    event_count = 10
    port = 5516
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
      event_count.times.collect{queue.pop}.sort_by{|event| event["message"]}
    end

    event_count.times do |i|
      insist { events[i]["message"] } == "#{i}"
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

    describe "register" do
      it "should register without errors" do
        expect { subject.register }.to_not raise_error
      end
    end

    describe "receive" do

      let(:nevents) { 10 }

      let(:events) do
        socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }

        result = helper.pipelineless_input(subject, nevents) do
          nevents.times do |i|
            socket.puts("msg #{i}")
            socket.flush
          end
        end
        socket.close rescue nil

        result
      end

      before(:each) do
        subject.register
      end

      it "should receive events been generated" do
        expect(events.size).to be(nevents)
        messages = events.map { |event| event["message"]}
        messages.each do |message|
          expect(message).to match(/msg \d+/)
        end
      end

      it "should add the host and port to the generated event" do
        events.each do |event|
          expect(event["host"]).to eq("127.0.0.1")
          expect(event["port"]).to be_an(Fixnum)
        end
      end

      describe "ssl" do

        let(:certificate) { helper.certificate }

        subject(:input) { LogStash::Plugin.lookup("input", "tcp").new(config) }

        let(:config) do
          {
            "host" => "0.0.0.0",
            "port" => port,
            "ssl_verify" => false,
            "ssl_enable" => true,
            "ssl_cert" => certificate[0].path,
            "ssl_key" => certificate[1].path
          }
        end

        let(:events) do
          socket = Stud::try(5.times) do
            ssl_context = OpenSSL::SSL::SSLContext.new
            socket = TCPSocket.new("127.0.0.1", port)
            OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
          end

          result = helper.pipelineless_input(subject, nevents) do
            socket.connect
            nevents.times do |i|
              socket.puts("msg #{i}")
              socket.flush
            end
          end
          socket.close rescue nil

          result
        end

        it "should receive events" do
          expect(events.size).to be(nevents)
        end

        it "should not contain sslsubject" do
          events.each do |event|
            expect(event["sslsubject"]).to be_nil
          end
        end

        describe "when ssl_verify is on" do

          let(:chain_of_certificates) { helper.chain_of_certificates }

          let(:ssl_context) do
            ssl_context      = OpenSSL::SSL::SSLContext.new
            ssl_context.cert = OpenSSL::X509::Certificate.new(client_certificate)
            ssl_context.key  = OpenSSL::PKey::RSA.new(client_key)
            ssl_context
          end

          context "and the verification fails" do

            let(:config) do
              {
                "host" => "0.0.0.0",
                "port" => port,
                "ssl_enable" => true,
                "ssl_verify" => true,
                "ssl_cert" => chain_of_certificates[:a_cert].path,
                "ssl_key" => chain_of_certificates[:a_key].path
              }
            end

            let(:client_certificate) { File.read(chain_of_certificates[:b_cert].path) }
            let(:client_key) { File.read(chain_of_certificates[:b_key].path) }

            let(:socket) do
              client = TCPSocket.new("127.0.0.1", port)
              OpenSSL::SSL::SSLSocket.new(client, ssl_context)
            end

            it "should raise an exception when connecting" do
              helper.pipelineless_input(subject, 0) do
                expect { socket.connect }.to raise_error
                socket.close rescue nil
              end
            end
          end

          context "and using the root CA" do

            let(:config) do
              {
                "host" => "0.0.0.0",
                "port" => port,
                "ssl_enable" => true,
                "ssl_verify" => true,
                "ssl_cert" => chain_of_certificates[:a_cert].path,
                "ssl_key" => chain_of_certificates[:a_key].path,
                "ssl_cacert" => chain_of_certificates[:root_ca].path
              }
            end

            let(:client_certificate) { File.read(chain_of_certificates[:aa_cert].path) }
            let(:client_key) { File.read(chain_of_certificates[:aa_key].path) }

            let(:events) do
              socket = Stud::try(5.times) do
                socket = TCPSocket.new("127.0.0.1", port)
                OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
              end

              result = helper.pipelineless_input(subject, nevents) do
                socket.connect
                nevents.times do |i|
                  socket.puts("msg #{i}")
                  socket.flush
                end
              end

              socket.close rescue nil

              result
            end

            it "should receive events" do
              expect(events.size).to be(nevents)
            end

            it "should contain sslsubject" do
              events.each do |event|
                expect(event["sslsubject"]).to eq("/DC=org/DC=ruby-lang/CN=RubyAA_Cert")
              end
            end
          end

          context "using an extra chain of certificates" do

            let(:config) do
              {
                "host" => "0.0.0.0",
                "port" => port,
                "ssl_enable" => true,
                "ssl_verify" => true,
                "ssl_cert" => chain_of_certificates[:b_cert].path,
                "ssl_key" => chain_of_certificates[:b_key].path,
                "ssl_extra_chain_certs" => [ chain_of_certificates[:root_ca].path, chain_of_certificates[:a_cert].path, chain_of_certificates[:b_cert].path ]
              }
            end

            let(:client_certificate) { File.read(chain_of_certificates[:c_cert].path) }
            let(:client_key) { File.read(chain_of_certificates[:c_key].path) }

            let(:events) do
              socket = Stud::try(5.times) do
                socket = TCPSocket.new("127.0.0.1", port)
                OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
              end

              result = helper.pipelineless_input(subject, nevents) do
                socket.connect
                nevents.times do |i|
                  socket.puts("msg #{i}")
                  socket.flush
                end
              end

              socket.close rescue nil

              result
            end

            it "should receive events" do
              expect(events.size).to be(nevents)
            end

            it "should contain sslsubject" do
              events.each do |event|
                expect(event["sslsubject"]).to eq("/DC=org/DC=ruby-lang/CN=RubyC_Cert")
              end
            end
          end
        end
      end
    end

    it_behaves_like "an interruptible input plugin" do
      let(:config) { { "port" => port } }
    end
  end
end
