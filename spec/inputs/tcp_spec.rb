# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/devutils/rspec/shared_examples"
require "socket"
require "timeout"
require "logstash/json"
require "logstash/inputs/tcp"
require "stud/try"
require "stud/task"
require "flores/pki"
require "openssl"

java_import "io.netty.handler.ssl.util.SelfSignedCertificate"

require_relative "../spec_helper"

require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

#Cabin::Channel.get(LogStash).subscribe(STDOUT)
#Cabin::Channel.get(LogStash).level = :debug
describe LogStash::Inputs::Tcp, :ecs_compatibility_support do

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

  ecs_compatibility_matrix(:disabled,:v1, :v8 => :v1) do |ecs_select|
    before(:each) do
      allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
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

      expect(events.length).to eq(event_count)
      events = events.sort_by {|e| e.get("message")} # the ordering of events in the queue is highly timing-dependent
      event_count.times do |i|
        event = events[i]

        aggregate_failures("event #{i}") do
          expect(event.get("message")).to eq("#{i} ☹")
          expect(event.get(ecs_select[disabled: "host", v1: "[@metadata][input][tcp][source][name]"])).to eq("localhost").or eq("ip6-localhost")
          expect(event.get(ecs_select[disabled: "[@metadata][ip_address]", v1: "[@metadata][input][tcp][source][ip]"])).to eq('127.0.0.1')
        end
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

      expect(events.length).to eq(event_count)
      events = events.sort_by {|e| e.get("message")} # the ordering of events in the queue is highly timing-dependent
      events.each_with_index do |event, i|
        aggregate_failures("event #{i}") do
          expect(event.get("message")).to eq("#{i} ☹")
          expect(event.get(ecs_select[disabled: "host",                    v1: "[@metadata][input][tcp][source][name]"])).to eq('1.2.3.4')
          expect(event.get(ecs_select[disabled: "[@metadata][ip_address]", v1: "[@metadata][input][tcp][source][ip]"  ])).to eq('1.2.3.4')
          expect(event.get(ecs_select[disabled: "port",                    v1: "[@metadata][input][tcp][source][port]"])).to eq('1234')
          expect(event.get(ecs_select[disabled: "proxy_host",              v1: "[@metadata][input][tcp][proxy][ip]"  ])).to eq('5.6.7.8')
          expect(event.get(ecs_select[disabled: "proxy_port",              v1: "[@metadata][input][tcp][proxy][port]"  ])).to eq('5678')
        end
      end
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

      aggregate_failures("event") do
        expect(event.get("hello")).to eq(data["hello"])
        expect(event).to include(ecs_select[disabled: "host",                    v1: "[@metadata][input][tcp][source][name]"])
        expect(event).to include(ecs_select[disabled: "[@metadata][ip_address]", v1: "[@metadata][input][tcp][source][ip]"  ])
      end
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
    aggregate_failures("event") do
      expect(event.get("message")).to have_attributes(size: 1, bytesize: 2, encoding: Encoding.find("UTF-8"))
      expect(event.get("message")).to eq("£")
    end
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

  context "LogStash::Inputs::Tcp new specs style" do

    before do
      srand(RSpec.configuration.seed)
    end

    let(:config) { { "port" => port } }
    subject { described_class.new(config) }
    let!(:helper) { TcpHelpers.new }

    after :each do
      subject.close rescue nil
    end

    describe "#register" do

      it "should register without errors" do
        expect { subject.register }.to_not raise_error
      end

      context "when using ssl" do
        let(:config) do
          {
            "host" => "127.0.0.1",
            "port" => port,
            "ssl_enable" => true,
            "ssl_cert" => certificate_file.path,
            "ssl_key" => key_file.path
          }
        end

        context "with pkcs#1 keys" do
          let(:pki) { Flores::PKI.generate }
          let(:certificate) { pki[0] }
          let(:key) { pki[1] }
          let(:certificate_file) { Stud::Temporary.file }
          let(:key_file) { Stud::Temporary.file }

          before do
            certificate_file.write(certificate)
            key_file.write(key)
            certificate_file.close
            key_file.close
          end

          it "should configure ssl manager correctly without errors" do
            expect { subject.register }.to_not raise_error
          end

          after do
            File.unlink(certificate_file.path)
            File.unlink(key_file.path)
          end
        end

        context "with pkcs#8 keys" do
          let(:ssc) { SelfSignedCertificate.new }
          let(:certificate_file) { ssc.certificate }
          let(:key_file) { ssc.private_key}

          it "should configure ssl manager correctly without errors" do
            expect { subject.register }.to_not raise_error
          end

          after do
            ssc.delete
          end
        end

        context "with multiple certificates with empty spaces in them" do
          let(:ssc) { SelfSignedCertificate.new }
          let(:certificate_file) { ssc.certificate }
          let(:key_file) { ssc.private_key}
          let(:ssc_2) { SelfSignedCertificate.new }
          let(:certificate_file_2) { ssc.certificate }
          let(:config) do
            {
              "host" => "127.0.0.1",
              "port" => port,
              "ssl_enable" => true,
              "ssl_cert" => certificate_file.path,
              "ssl_key" => key_file.path
            }
          end
          before(:each) do
            File.open(certificate_file.path, "a") do |file|
              path = ssc_2.certificate.path
              file.puts("\n")
              file.puts(IO.read(path))
              file.puts("\n")
            end
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end
        end

        context "encrypted (AES-156) key" do
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/encrypted_aes256.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/encrypted_aes256.key', File.dirname(__FILE__)),
                "ssl_key_passphrase" => '1234',
            }
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end

        end

        context "encrypted (SEED) key" do # algorithm not supported by Sun provider
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/encrypted_seed.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/encrypted_seed.key', File.dirname(__FILE__)),
                "ssl_key_passphrase" => '1234',
            }
          end

          it "should register without errors" do
            pending # newer BC should be able to read this
            expect { subject.register }.to_not raise_error
          end

        end

        context "encrypted (DES) key" do
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/encrypted_des.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/encrypted_des.key', File.dirname(__FILE__)),
                "ssl_key_passphrase" => '1234',
            }
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end

        end

        context "encrypted PKCS#8 key" do
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/encrypted-pkcs8.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/encrypted-pkcs8.key', File.dirname(__FILE__)),
                "ssl_key_passphrase" => '1234',
            }
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end

        end

        # NOTE: only BC provider can read the legacy (OpenSSL) format
        context "encrypted PKCS#5 v1.5 key" do # openssl pkcs8 -topk8 -v1 PBE-MD5-DES
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/encrypted-pkcs5v15.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/encrypted-pkcs5v15.key', File.dirname(__FILE__)),
                "ssl_key_passphrase" => '1234',
            }
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end

        end

        context "small (legacy) key" do
          let(:config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => File.expand_path('../fixtures/small.crt', File.dirname(__FILE__)),
                "ssl_key" => File.expand_path('../fixtures/small.key', File.dirname(__FILE__)),
            }
          end

          it "should register without errors" do
            expect { subject.register }.to_not raise_error
          end

        end
      end
    end

    describe "#receive" do
      shared_examples "receiving events" do
        # TODO(sissel): Implement normal event-receipt tests as as a shared example
      end

      context "when ssl_enable is true" do
        let(:input) { subject }
        let(:queue) { Queue.new }
        before(:each) { subject.register }

        context "when using a certificate chain" do
          chain_of_certificates = TcpHelpers.new.chain_of_certificates

          let(:tcp) do
            Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
          end
          let(:sslcontext) do
            sslcontext = OpenSSL::SSL::SSLContext.new
            sslcontext.verify_mode = OpenSSL::SSL::VERIFY_PEER
            sslcontext.ca_file = chain_of_certificates[:root_ca].path
            sslcontext.cert = OpenSSL::X509::Certificate.new(File.read(chain_of_certificates[:aa_cert].path))
            sslcontext.key = OpenSSL::PKey::RSA.new(File.read(chain_of_certificates[:aa_key].path))
            sslcontext
          end
          let(:sslsocket) { OpenSSL::SSL::SSLSocket.new(tcp, sslcontext) }
          let(:message) { "message to #{port}" }

          let(:base_config) do
            {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => chain_of_certificates[:b_cert].path,
                "ssl_key" => chain_of_certificates[:b_key].path,
                "ssl_extra_chain_certs" => [ chain_of_certificates[:a_cert].path ],
                "ssl_certificate_authorities" => [ chain_of_certificates[:root_ca].path ]
            }
          end

          context "with a non encrypted private key" do
            let(:config) do
              base_config.merge "ssl_verify" => true
            end
            it "should be able to connect and write data" do
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(result.first.get("message")).to eq(message)
            end
          end

          context "when using an encrypted private pkcs1 key" do
            let(:config) do
              {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => chain_of_certificates[:be_cert].path,
                "ssl_key" => chain_of_certificates[:be_key].path,
                "ssl_key_passphrase" => "passpasspassword",
                "ssl_extra_chain_certs" => [ chain_of_certificates[:a_cert].path ],
                "ssl_certificate_authorities" => [ chain_of_certificates[:root_ca].path ],
                "ssl_verify" => true
              }
            end
            it "should be able to connect and write data" do
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(result.first.get("message")).to eq(message)
            end
          end

          context "when using an encrypted private pkcs8 key" do
            let(:config) do
              {
                "host" => "127.0.0.1",
                "port" => port,
                "ssl_enable" => true,
                "ssl_cert" => chain_of_certificates[:be_cert].path,
                "ssl_key" => chain_of_certificates[:be_key_pkcs8].path,
                "ssl_key_passphrase" => "passpasspassword",
                "ssl_extra_chain_certs" => [ chain_of_certificates[:a_cert].path ],
                "ssl_certificate_authorities" => [ chain_of_certificates[:root_ca].path ],
                "ssl_verify" => true
              }
            end
            it "should be able to connect and write data" do
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(result.first.get("message")).to eq(message)
            end
          end

          context "with enforced protocol version" do
            let(:config) do
              base_config.merge 'ssl_supported_protocols' => [ tls_version ]
            end

            let(:tls_version) { 'TLSv1.3' }

            it "should be able to connect and write data" do
              used_tls_protocol = nil
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                used_tls_protocol = sslsocket.session.to_java(javax.net.ssl.SSLSession).getProtocol
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(used_tls_protocol).to eql tls_version
            end
          end

          context "with enforced protocol range" do
            let(:config) do
              base_config.merge 'ssl_supported_protocols' => [ 'TLSv1.3', 'TLSv1.2' ]
            end
            let(:sslcontext) do
              super().tap { |ctx| ctx.ssl_version = 'TLSv1.2' }
            end

            it "should be able to connect and write data" do
              used_tls_protocol = nil
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                used_tls_protocol = sslsocket.session.to_java(javax.net.ssl.SSLSession).getProtocol
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(used_tls_protocol).to eql 'TLSv1.2'
            end
          end if TcpHelpers.tls13_available_by_default? # till CI testing against 6.x

          context "with unsupported client protocol" do
            let(:config) do
              base_config.merge 'ssl_supported_protocols' => [ 'TLSv1.2' ]
            end
            let(:sslcontext) do
              super().tap { |ctx| ctx.ssl_version = 'TLSv1.1' }
            end

            it "should not be able to connect" do
              TcpHelpers.pipelineless_input(subject, 0) do
                expect { sslsocket.connect }.to raise_error(OpenSSL::SSL::SSLError, /No appropriate protocol|protocol_version/i)
                sslsocket.close
                tcp.close
              end
            end
          end

          context "with specified cipher suites" do
            let(:config) do
              base_config.merge 'ssl_cipher_suites' => [ cipher_suite ]
            end

            let(:cipher_suite) { 'TLS_RSA_WITH_AES_128_GCM_SHA256' }

            it "should be able to connect and write data" do
              used_cipher_suite = nil
              result = TcpHelpers.pipelineless_input(subject, 1) do
                sslsocket.connect
                sslsocket.write("#{message}\n")
                used_cipher_suite = sslsocket.session.to_java(javax.net.ssl.SSLSession).getCipherSuite
                tcp.flush
                sslsocket.close
                tcp.close
              end
              expect(result.size).to eq(1)
              expect(used_cipher_suite).to eql cipher_suite
            end
          end

          context "with unsupported client cipher" do
            let(:config) do
              base_config.merge 'ssl_cipher_suites' => [ 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' ]
            end

            let(:sslcontext) do
              super().tap { |ctx| ctx.ciphers = [ 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' ] }
            end

            it "should not be able to connect" do
              TcpHelpers.pipelineless_input(subject, 0) do
                expect { sslsocket.connect }.to raise_error(OpenSSL::SSL::SSLError, /handshake_failure|no cipher match/i)
                sslsocket.close
                tcp.close
              end
            end
          end

        end

        context "with a poorly-behaving client" do
          let!(:input_task) { Stud::Task.new { input.run(queue) } }

          context "that disconnects before doing TLS handshake" do
            before do
              client = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
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
          end

          context "that sends garbage instead of TLS handshake" do
            let!(:input_task) { Stud::Task.new { input.run(queue) } }
            let(:max_length) { 1000 }
            let(:garbage) { Flores::Random.iterations(max_length).collect { Flores::Random.integer(1...255) }.pack("C*") }
            before do
              # Assertion to verify this test is actually sending something.
              expect(garbage.length).to be > 0

              client = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
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

  context 'ssl context (client mode)' do

    let(:chain_of_certificates) do
      TcpHelpers.new.chain_of_certificates
    end

    let(:config) do
      {
          "host" => "127.0.0.1",
          "port" => port,
          "mode" => 'client',
          "ssl_enable" => true,
          "ssl_cert" => chain_of_certificates[:b_cert].path,
          "ssl_key" => chain_of_certificates[:b_key].path,
          "ssl_extra_chain_certs" => [ chain_of_certificates[:a_cert].path ],
          "ssl_certificate_authorities" => [ chain_of_certificates[:root_ca].path ]
      }
    end

    subject(:plugin) { LogStash::Inputs::Tcp.new(config) }

    let(:ssl_context) { plugin.send :ssl_context }

    context "with cipher suites" do
      let(:config) do
        super().merge 'ssl_cipher_suites' => [ cipher_suite ]
      end

      let(:cipher_suite) { 'TLS_RSA_WITH_AES_128_GCM_SHA256' }

      it "sets ciphers" do
        cipher_ary = ssl_context.ciphers.first
        expect( cipher_ary[0] ).to eql 'AES128-GCM-SHA256'
      end

    end

    context "with forced protocol" do
      let(:config) do
        super().merge 'ssl_supported_protocols' => [ 'TLSv1.1' ]
      end

      it "limits protocol selection" do
        if OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3
          ssl_context = subject.send :ssl_context
          expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_3).to_not eql 0
          expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to_not eql 0
          expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
        else
          ssl_context = OpenSSL::SSL::SSLContext.new
          allow(subject).to receive(:new_ssl_context).and_return(ssl_context)
          expect(ssl_context).to receive(:max_version=).with(:'TLS1_2').and_call_original
          ssl_context = subject.send :ssl_context
          expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to_not eql 0
          expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
        end
      end

    end

    context "with protocol range" do
      let(:config) do
        super().merge 'ssl_supported_protocols' => [ 'TLSv1.3', 'TLSv1.1', 'TLSv1.2' ]
      end

      it "does not limit protocol selection (except min_version)" do
        ssl_context = OpenSSL::SSL::SSLContext.new
        allow(subject).to receive(:new_ssl_context).and_return(ssl_context)
        expect(ssl_context).to receive(:min_version=).with(:'TLS1_1').and_call_original
        ssl_context = subject.send :ssl_context
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_3).to eql 0 if OpenSSL::SSL.const_defined? :OP_NO_TLSv1_3
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_2).to eql 0
        expect(ssl_context.options & OpenSSL::SSL::OP_NO_TLSv1_1).to eql 0
      end
    end

  end

end
