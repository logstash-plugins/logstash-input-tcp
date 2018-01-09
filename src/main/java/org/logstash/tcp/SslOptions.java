package org.logstash.tcp;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class SslOptions {

    private final boolean isSslEnabled;
    private final boolean shouldVerify;
    private final String sslCert;
    private final String sslKey;
    private final String sslKeyPassphrase;
    private final String[] sslExtraChainCerts;

    private SslOptions(SslOptionsBuilder builder) {
        this.isSslEnabled = builder.isSslEnabled;
        this.shouldVerify = builder.shouldVerify;
        this.sslCert = builder.sslCert;
        this.sslKey = builder.sslKey;
        this.sslKeyPassphrase = builder.sslKeyPassphrase;
        this.sslExtraChainCerts = builder.sslExtraChainCerts;
    }

    public boolean isSslEnabled() {
        return isSslEnabled;
    }

    public boolean isShouldVerify() {
        return shouldVerify;
    }

    public String getSslCert() {
        return sslCert;
    }

    public String getSslKey() {
        return sslKey;
    }

    public String getSslKeyPassphrase() {
        return sslKeyPassphrase;
    }

    public String[] getSslExtraChainCerts() {
        return sslExtraChainCerts;
    }

    public static SslOptionsBuilder builder() {
        return new SslOptionsBuilder();
    }

    public SslContext toSslContext() throws Exception {
        if (!isSslEnabled) {
            return null;
        }

        SslContextBuilder sslContextBuilder = SslContextBuilder.forServer(
                new File(getSslCert()), new File(getSslKey()), getSslKeyPassphrase());

        if (getSslExtraChainCerts().length > 0) {
            X509Certificate[] certChain = new X509Certificate[getSslExtraChainCerts().length];
            for (int k = 0; k < getSslExtraChainCerts().length; k++) {
                try (InputStream inStream = new FileInputStream(getSslExtraChainCerts()[k])) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    certChain[k] = (X509Certificate) cf.generateCertificate(inStream);
                }
            }
            sslContextBuilder = sslContextBuilder.trustManager(certChain);
        }
        sslContextBuilder.clientAuth(isShouldVerify() ? ClientAuth.REQUIRE : ClientAuth.NONE);
        return sslContextBuilder.build();
    }

    public static final class SslOptionsBuilder {
        private boolean isSslEnabled = false;
        private boolean shouldVerify = true;
        private String sslCert;
        private String sslKey;
        private String sslKeyPassphrase;
        private String[] sslExtraChainCerts;

        public SslOptionsBuilder setIsSslEnabled(boolean isSslEnabled) {
            this.isSslEnabled = isSslEnabled;
            return this;
        }

        public SslOptionsBuilder setShouldVerify(boolean shouldVerify) {
            this.shouldVerify = shouldVerify;
            return this;
        }

        public SslOptionsBuilder setSslCert(String sslCert) {
            this.sslCert = sslCert;
            return this;
        }

        public SslOptionsBuilder setSslKey(String sslKey) {
            this.sslKey = sslKey;
            return this;
        }

        public SslOptionsBuilder setSslKeyPassphrase(String sslKeyPassphrase) {
            this.sslKeyPassphrase = sslKeyPassphrase;
            return this;
        }

        public SslOptionsBuilder setSslExtraChainCerts(String[] sslExtraChainCerts) {
            this.sslExtraChainCerts = sslExtraChainCerts;
            return this;
        }

        public SslOptions build() {
            return new SslOptions(this);
        }
    }

}
