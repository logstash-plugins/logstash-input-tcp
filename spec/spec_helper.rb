# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "tempfile"

# this has been taken from the udp input, it should be DRYed

class TcpHelpers

  def pipelineless_input(plugin, size, &block)
    queue = Queue.new
    input_thread = Thread.new do
      plugin.run(queue)
    end
    block.call
    sleep 0.1 while queue.size != size
    result = size.times.inject([]) do |acc|
      acc << queue.pop
    end
    plugin.do_stop
    input_thread.join
    result
  end

  def certificate
    certificate, key = Flores::PKI.generate("CN=localhost", { :key_size => 2048 })
    [new_temp_file('cert', certificate), new_temp_file('key', key)]
  end

  private

  def new_temp_file(name, data)
    file = Tempfile.new(name)
    file.write(data)
    file.rewind
    file
  end
end
