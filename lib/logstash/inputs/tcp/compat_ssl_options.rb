require 'openssl'

java_import 'io.netty.handler.ssl.ClientAuth'
java_import 'io.netty.handler.ssl.SslContextBuilder'
java_import 'java.io.FileInputStream'
java_import 'java.io.FileReader'
java_import 'java.security.cert.CertificateFactory'
java_import 'java.security.cert.X509Certificate'
java_import 'org.bouncycastle.asn1.pkcs.PrivateKeyInfo'
java_import 'org.bouncycastle.openssl.PEMKeyPair'
java_import 'org.bouncycastle.openssl.PEMParser'
java_import 'org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter'

# Simulate a normal SslOptions builder:
#
#     ssl_context = SslOptions.builder
#       .set_is_ssl_enabled(@ssl_enable)
#       .set_should_verify(@ssl_verify)
#       .set_ssl_cert(@ssl_cert)
#       .set_ssl_key(@ssl_key)
#       .set_ssl_key_passphrase(@ssl_key_passphrase.value)
#       .set_ssl_extra_chain_certs(@ssl_extra_chain_certs.to_java(:string))
#       .set_ssl_certificate_authorities(@ssl_certificate_authorities.to_java(:string))
#       .build.toSslContext()
class SslOptions
  def self.builder
    new
  end

  def set_is_ssl_enabled(boolean)
    @ssl_enabled = boolean
    self
  end

  def set_should_verify(boolean)
    @ssl_verify = boolean
    self
  end

  def set_ssl_cert(path)
    @ssl_cert_path = path
    self
  end

  def set_ssl_key(path)
    @ssl_key_path = path
    self
  end

  def set_ssl_key_passphrase(passphrase)
    @ssl_key_passphrase = passphrase
    self
  end

  def set_ssl_extra_chain_certs(certs)
    @ssl_extra_chain_certs = certs
    self
  end

  def set_ssl_certificate_authorities(certs)
    @ssl_certificate_authorities = certs
    self
  end

  def build; self; end

  def toSslContext
    return nil unless @ssl_enabled

    # create certificate object
    cf = CertificateFactory.getInstance("X.509")
    cert_chain = []
    cert_chain << cf.generateCertificate(FileInputStream.new(@ssl_cert_path))

    # convert key from pkcs1 to pkcs8 and get PrivateKey object
    pem_parser = PEMParser.new(FileReader.new(@ssl_key_path))

    case obj = pem_parser.read_object
    when PEMKeyPair # likely pkcs#1
      private_key = JcaPEMKeyConverter.new.get_key_pair(obj).private
    when PrivateKeyInfo # likely pkcs#8
      private_key = JcaPEMKeyConverter.new.get_private_key(obj)
    else
      raise "Could not recognize 'ssl_key' format. Class: #{obj.class}"
    end

    @ssl_extra_chain_certs.each do |cert|
      cert_chain << cf.generateCertificate(FileInputStream.new(cert))
    end
    sslContextBuilder = SslContextBuilder.forServer(private_key, @ssl_key_passphrase, cert_chain.to_java(java.security.cert.X509Certificate))

    trust_certs = @ssl_certificate_authorities.map do |cert|
      cf.generateCertificate(FileInputStream.new(cert))
    end

    if trust_certs.any?
      sslContextBuilder.trustManager(trust_certs.to_java(java.security.cert.X509Certificate))
    end

    sslContextBuilder.clientAuth(@ssl_verify ? ClientAuth::REQUIRE : ClientAuth::NONE)
    sslContextBuilder.build()
  end
end
