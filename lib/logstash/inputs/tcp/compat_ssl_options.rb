require 'openssl'

java_import 'io.netty.handler.ssl.ClientAuth'
java_import 'io.netty.handler.ssl.SslContextBuilder'
java_import 'java.io.FileInputStream'
java_import 'java.io.FileReader'
java_import 'java.security.cert.CertificateFactory'
java_import 'org.bouncycastle.openssl.PEMParser'
java_import 'org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter'
java_import 'java.security.cert.X509Certificate'

# API to simulate:
#
#     ssl_context = SslOptions.builder
#       .set_is_ssl_enabled(@ssl_enable)
#       .set_should_verify(@ssl_verify)
#       .set_ssl_cert(@ssl_cert)
#       .set_ssl_key(@ssl_key)
#       .set_ssl_key_passphrase(@ssl_key_passphrase.value)
#       .set_ssl_extra_chain_certs(@ssl_extra_chain_certs.to_java(:string))
#       .build.toSslContext()
class CompatSslOptions
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

  def build; self; end

  def toSslContext
    return nil unless @ssl_enabled

    # create certificate object
    cf = CertificateFactory.getInstance("X.509")
    cer = cf.generateCertificate(FileInputStream.new(@ssl_cert_path))

    # convert key from pkcs1 to pkcs8 and get PrivateKey object
    pem_parser = PEMParser.new(FileReader.new(@ssl_key_path))
    obj = pem_parser.read_object
    kp = JcaPEMKeyConverter.new.get_key_pair(obj)
    private_key = kp.private

    sslContextBuilder = SslContextBuilder.forServer(private_key, @ssl_key_passphrase, cer)

    if (@ssl_extra_chain_certs.size > 0)
      cert_chain = @ssl_extra_chain_certs.map do |cert|
        cf.generateCertificate(FileInputStream.new(cert))
      end
      sslContextBuilder = sslContextBuilder.trustManager(cert_chain.to_java(java.security.cert.X509Certificate))
    end
    sslContextBuilder.clientAuth(@ssl_verify ? ClientAuth::REQUIRE : ClientAuth::NONE)
    sslContextBuilder.build()
  end
end
