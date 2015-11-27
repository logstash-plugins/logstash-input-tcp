# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "tempfile"
require "stud/temporary"

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

  def chain_of_certificates
    root_ca, root_key = build_root_ca
    a_cert, a_key = build_certificate(root_ca, root_key, "A_Cert")
    b_cert, b_key = build_certificate(a_cert, a_key, "B_Cert")
    c_cert, c_key = build_certificate(b_cert, b_key, "C_Cert")
    { :root_ca => new_temp_file('', root_ca), :root_key => new_temp_file('', root_key),
      :a_cert => new_temp_file('', a_cert), :a_key => new_temp_file('', a_key),
      :b_cert => new_temp_file('', b_cert), :b_key => new_temp_file('', b_key),
      :c_cert => new_temp_file('', c_cert), :c_key => new_temp_file('', c_key)}
  end

  private

  def new_temp_file(name, data)
    file = Stud::Temporary.file
    file.write(data)
    file.rewind
    file
  end

  def build_certificate(root_ca, root_key=nil, name="")
    key = ( root_key.nil? ? OpenSSL::PKey::RSA.new(2048) : root_key )
    options = { :serial => 2, :subject => "/DC=org/DC=ruby-lang/CN=Ruby#{name}", :key => key, :issuer => root_ca.subject}
    cert = new_certificate(options)
    add_ca_extensions(cert, nil, root_ca)
    [ cert.sign(key, OpenSSL::Digest::SHA256.new), key ]
  end

  def build_root_ca
    key = OpenSSL::PKey::RSA.new(2048)
    options = { :serial => 1, :subject => "/DC=org/DC=ruby-lang/CN=Ruby CA", :key => key}
    ca = new_certificate(options)
    add_ca_extensions(ca)
    [ ca.sign(key, OpenSSL::Digest::SHA256.new), key ]
  end

  def new_certificate(options)
    cert  = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = options.fetch(:serial, 1)
    cert.subject = OpenSSL::X509::Name.parse(options.fetch(:subject, "/DC=org/DC=ruby-lang/CN=Ruby CA"))
    cert.issuer  = options.fetch(:issuer, cert.subject)
    cert.public_key = options[:key].public_key
    cert.not_before = Time.now
    cert.not_after  = cert.not_before + 2 * 365 * 86400
    cert
  end

  def add_ca_extensions(certificate, subject=nil, issuer=nil)
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = (subject.nil? ? certificate : subject)
    factory.issuer_certificate  = (issuer.nil?  ? certificate : issuer)

    certificate.add_extension(factory.create_extension("basicConstraints","CA:TRUE",true))
    certificate.add_extension(factory.create_extension("keyUsage","keyCertSign, cRLSign, digitalSignature", true))
    certificate.add_extension(factory.create_extension("subjectKeyIdentifier","hash",false))
    certificate.add_extension(factory.create_extension("authorityKeyIdentifier","keyid:always",false))
  end

end
