#!/usr/bin/env ruby

require "openssl"

class CertificateBuilder

  def build(root_ca, root_key=nil, name="", ca=false)
    key = ( root_key.nil? ? OpenSSL::PKey::RSA.new(2048) : root_key )
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=Ruby#{name}")
    cert.issuer = root_ca.subject # root CA is the issuer
    cert.public_key = key.public_key
    cert.not_before = Time.now
    cert.not_after = cert.not_before + 1 * 365 * 86400 # 1 years validity

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = root_ca
    cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    cert.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign, digitalSignature", true))
    cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    cert.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    [ cert.sign(key, OpenSSL::Digest::SHA256.new), key ]
  end

  def build_root_ca
    key = OpenSSL::PKey::RSA.new(2048)
    ca  = OpenSSL::X509::Certificate.new
    ca.version = 2
    ca.serial = 1
    ca.subject = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=Ruby CA")
    ca.issuer  = ca.subject
    ca.public_key = key.public_key
    ca.not_before = Time.now
    ca.not_after  = ca.not_before + 2 * 365 * 86400

    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = ca
    ef.issuer_certificate = ca
    ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
    ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
    ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
    ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
    [ ca.sign(key, OpenSSL::Digest::SHA256.new), key ]
  end
end

if __FILE__ == $0

  builder = CertificateBuilder.new
  root_ca, root_key = builder.build_root_ca

  ## build a chain of certificates
  a_cert, a_key  = builder.build(root_ca, root_key, "A_Cert", true)
  b_cert, b_key  = builder.build(a_cert, a_key, "B_Cert", true)
  c_cert, _  = builder.build(b_cert, b_key, "C_Cert")

  ## validate c_cert

  store = OpenSSL::X509::Store.new
  store.set_default_paths
  store.add_cert(root_ca)
  #store.add_cert(a_cert)
  store.add_cert(b_cert)

  puts store.verify(a_cert)
  puts store.error_string
  puts store.verify(b_cert)
  puts store.error_string
  puts store.verify(c_cert)
  puts store.error_string

end
