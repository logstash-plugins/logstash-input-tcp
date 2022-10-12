package org.logstash.tcp;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import javax.crypto.Cipher;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SslContextBuilder {

    private static final String[] NULL_STRING_ARRAY = new String[0];

    private final static Logger logger = LogManager.getLogger(SslContextBuilder.class);

    public static List<String> getSupportedCipherSuites() {
        return Arrays.asList(
            ((javax.net.ssl.SSLServerSocketFactory) SSLServerSocketFactory.getDefault()).getSupportedCipherSuites()
        );
    }

    private boolean sslEnabled;
    private boolean shouldVerify;

    private String certPath;
    private String keyPath;

    private char[] keyPassword;

    private String[] certificateAuthorities = NULL_STRING_ARRAY;
    private String[] extraChainCerts = NULL_STRING_ARRAY;

    private String[] supportedProtocols = NULL_STRING_ARRAY;
    private String[] cipherSuites = NULL_STRING_ARRAY;

    public SslContextBuilder setSslEnabled(boolean enabled) {
        this.sslEnabled = enabled;
        return this;
    }

    public SslContextBuilder setShouldVerify(boolean verify) {
        this.shouldVerify = verify;
        return this;
    }

    public SslContextBuilder setSslCert(String path) {
        this.certPath = path;
        return this;
    }

    public SslContextBuilder setSslKey(String path) {
        this.keyPath = path;
        return this;
    }

    public SslContextBuilder setSslKeyPassword(String password) {
        this.keyPassword = password == null ? null : password.toCharArray();
        return this;
    }

    public SslContextBuilder setSslCertificateAuthorities(String[] paths) {
        this.certificateAuthorities = paths;
        return this;
    }

    public SslContextBuilder setSslExtraChainCerts(String[] paths) {
        this.extraChainCerts = paths;
        return this;
    }

    public SslContextBuilder setSslSupportedProtocols(String[] protocols) {
        this.supportedProtocols = protocols;
        return this;
    }

    public SslContextBuilder setSslCipherSuites(String[] suites) {
        if (suites.length > 0) {
            final Set<String> supportedCipherSuites = new HashSet<>(getSupportedCipherSuites());
            for (String cipher : suites) {
                if (supportedCipherSuites.contains(cipher)) {
                    logger.debug("{} cipher is supported", cipher);
                } else {
                    throw new IllegalArgumentException("Cipher `" + cipher + "` is not available");
                }
            }
        }

        this.cipherSuites = suites;
        return this;
    }

    public SslContext buildContext() throws Exception {
        if (!sslEnabled) return null;

        if (certPath == null) {
            throw new IllegalArgumentException("missing ssl_cert");
        }
        if (keyPath == null) {
            throw new IllegalArgumentException("missing ssl_key");
        }

        // NOTE: decrypting openssl key-pair (PEMEncryptedKeyPair) assumes the BC provider
        installBouncyCastleProvider();

        // Check key strength
        if (Cipher.getMaxAllowedKeyLength("AES") <= 128) {
            logger.warn("JCE Unlimited Strength Jurisdiction Policy not installed - max key length is 128 bits");
        }

        // create certificate object
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        List<Certificate> certChain = getCertificatesFromFile(certPath, certFactory);
        if (certChain.isEmpty()) {
            logger.warn("Failed to read certificate from path: {}", certPath);
            throw new IllegalArgumentException("failed to read certificate from ssl_cert path");
        }

        // convert key from pkcs1 to pkcs8 and get PrivateKey object
        final PrivateKey privateKey;

        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        converter.setProvider(new BouncyCastleProvider());

        Object obj = new PEMParser(new FileReader(keyPath)).readObject();
        if (obj instanceof PEMKeyPair) { // unencrypted pkcs#1
            privateKey = converter.getKeyPair((PEMKeyPair) obj).getPrivate();
        } else if (obj instanceof PrivateKeyInfo) { // unencrypted pkcs#8
            privateKey = converter.getPrivateKey((PrivateKeyInfo) obj);
        } else if (obj instanceof PEMEncryptedKeyPair) { // encrypted pkcs#1
            PEMDecryptorProvider decryptor = new JcePEMDecryptorProviderBuilder().build(keyPassword);
            PEMKeyPair keyPair = ((PEMEncryptedKeyPair) obj).decryptKeyPair(decryptor);
            privateKey = converter.getKeyPair(keyPair).getPrivate();
        } else if (obj instanceof PKCS8EncryptedPrivateKeyInfo) { // encrypted pkcs#8
            InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyPassword);
            PrivateKeyInfo keyInfo = ((PKCS8EncryptedPrivateKeyInfo) obj).decryptPrivateKeyInfo(decryptor);
            privateKey = converter.getPrivateKey(keyInfo);
        } else {
            throw new IllegalArgumentException("unexpected key format (" + (obj == null ? null : obj.getClass()) + ")");
        }

        for (String certPath : extraChainCerts) {
            certChain.addAll( getCertificatesFromFile(certPath, certFactory) );
        }

        io.netty.handler.ssl.SslContextBuilder sslContextBuilder =
                io.netty.handler.ssl.SslContextBuilder.forServer(privateKey,
                        keyPassword == null ? null : new String(keyPassword),
                        certChain.toArray(new X509Certificate[certChain.size()])
                );

        List<Certificate> trustedCerts = new ArrayList<>();
        for (String certPath : certificateAuthorities) {
            trustedCerts.addAll( getCertificatesFromFile(certPath, certFactory) );
        }

        if (!trustedCerts.isEmpty()) {
            sslContextBuilder.trustManager(trustedCerts.toArray(new X509Certificate[trustedCerts.size()]));
        }

        sslContextBuilder.clientAuth(shouldVerify ? ClientAuth.REQUIRE : ClientAuth.NONE);

        if (supportedProtocols.length > 0) sslContextBuilder.protocols(supportedProtocols);
        if (cipherSuites.length > 0) sslContextBuilder.ciphers(Arrays.asList(cipherSuites));

        try {
            return sslContextBuilder.build();
        } catch (SSLException e) {
            logger.debug("Failed to initialize SSL", e);
            // unwrap generic wrapped exception from Netty's JdkSsl{Client|Server}Context
            if ("failed to initialize the server-side SSL context".equals(e.getMessage()) ||
                "failed to initialize the client-side SSL context".equals(e.getMessage())) {
                // Netty catches Exception and simply wraps: throw new SSLException("...", e);
                if (e.getCause() instanceof Exception) throw (Exception) e.getCause();
            }
            throw e;
        } catch (Exception e) {
            logger.debug("Failed to initialize SSL", e);
            throw e;
        }
    }

    private static List<Certificate> getCertificatesFromFile(final String file, final CertificateFactory factory)
        throws IOException, CertificateException {
        final ArrayList<Certificate> certificates = new ArrayList<>();
        final FileInputStream fis = new FileInputStream(file);
        try {
            while (fis.available() > 0) {
                try {
                    certificates.add( factory.generateCertificate(fis) );
                } catch (CertificateException e) {
                    logger.debug("Failed to read certificate", e);
                    Throwable cause = e.getCause();
                    if (cause != null && "Empty input".equals(cause.getMessage())) {
                        logger.debug("Detected empty input while reading certificate (" + cause + ")");
                        continue;
                    }
                    throw e;
                }
            }
        } finally {
            fis.close();
        }
        return certificates;
    }

    private static void installBouncyCastleProvider() {
        synchronized (Security.class) {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }
    }

}
