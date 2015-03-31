# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "socket"
require "timeout"
require "logstash/json"
require "logstash/inputs/tcp"
require 'stud/try'

describe LogStash::Inputs::Tcp do


  context "codec (PR #1372)" do
    it "switches from plain to line" do
      require "logstash/codecs/plain"
      require "logstash/codecs/line"
      plugin = LogStash::Inputs::Tcp.new("codec" => LogStash::Codecs::Plain.new, "port" => 0)
      plugin.register
      insist { plugin.codec }.is_a?(LogStash::Codecs::Line)
      plugin.teardown
    end
    it "switches from json to json_lines" do
      require "logstash/codecs/json"
      require "logstash/codecs/json_lines"
      plugin = LogStash::Inputs::Tcp.new("codec" => LogStash::Codecs::JSON.new, "port" => 0)
      plugin.register
      insist { plugin.codec }.is_a?(LogStash::Codecs::JSONLines)
      plugin.teardown
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

    events = input(conf) do |pipeline, queue|
      socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
      (1..5).each do |idx|
        data["idx"] = idx
        socket.puts(LogStash::Json.dump(data) + "\n")
      end
      socket.close

      (1..5).map{queue.pop}
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

  it "should connection threads are cleaned up when connection is closed" do
    event_count = 10
    port = 5517
    conf = <<-CONFIG
      input {
        tcp {
          port => #{port}
        }
      }
    CONFIG

    input(conf) do |pipeline, queue|
      inputs = pipeline.instance_variable_get("@inputs")
      insist { inputs.size } == 1

      sockets = event_count.times.map do |i|
        socket = Stud::try(5.times) { TCPSocket.new("127.0.0.1", port) }
        socket.puts("#{i}")
        socket.flush
        socket
      end

      client_threads = inputs[0].instance_variable_get("@client_threads")

      # close all sockets and make sure there is not more pending threads
      sockets.each{|socket| socket.close}

      Timeout.timeout(1) {sleep 0.1 while client_threads.size > 0}
      insist { client_threads.size } == 0 # this check is actually useless per previous line
    end
  end
end
