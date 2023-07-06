package org.logstash.tcp;

import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import org.junit.jupiter.api.Test;
import org.logstash.tcp.SslContextBuilder.SslClientAuthentication;

import javax.net.ssl.SSLEngine;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.logstash.tcp.SslContextBuilder.getSupportedCipherSuites;
import static org.logstash.tcp.TestUtils.resourcePath;

class SslContextBuilderTest {
    private static final String CERTIFICATE = resourcePath("host.crt");
    private static final String KEY = resourcePath("host.key");
    private static final String KEY_ENCRYPTED = resourcePath("host.enc.key");
    private static final String KEY_ENCRYPTED_PASS = "1234";

    @Test
    void testConstructorShouldFailWhenCertificatePathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> new SslContextBuilder("foo-bar.crt", KEY_ENCRYPTED, KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Certificate file cannot be read. Please confirm the user running Logstash has permissions to read: foo-bar.crt",
                thrown.getMessage()
        );
    }

    @Test
    void testConstructorShouldFailWhenKeyPathIsInvalid() {
        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> new SslContextBuilder(CERTIFICATE, "invalid.key", KEY_ENCRYPTED_PASS)
        );

        assertEquals(
                "Private key file cannot be read. Please confirm the user running Logstash has permissions to read: invalid.key",
                thrown.getMessage()
        );
    }

    @Test
    void testSetCipherSuitesShouldNotFailIfAllCiphersAreValid() {
        final SslContextBuilder sslContextBuilder = createSslContextBuilder();
        assertDoesNotThrow(() -> sslContextBuilder.setCipherSuites(getSupportedCipherSuites().toArray(new String[0])));
    }

    @Test
    void testSetCipherSuitesShouldThrowIfAnyCiphersIsInValid() {
        final SslContextBuilder sslContextBuilder = createSslContextBuilder();
        List<String> supportedCipherSuites = getSupportedCipherSuites();
        final String[] ciphers = supportedCipherSuites
                .toArray(new String[supportedCipherSuites.size() + 1]);

        ciphers[ciphers.length - 1] = "TLS_INVALID_CIPHER";

        final IllegalArgumentException thrown = assertThrows(
                IllegalArgumentException.class,
                () -> sslContextBuilder.setCipherSuites(ciphers)
        );

        assertEquals("Cipher `TLS_INVALID_CIPHER` is not available", thrown.getMessage());
    }

    @Test
    void testSetProtocols() {
        final SslContextBuilder sslContextBuilder = createSslContextBuilder();
        assertArrayEquals(new String[]{}, sslContextBuilder.getSupportedProtocols());

        sslContextBuilder.setSupportedProtocols(new String[]{"TLSv1.1"});
        assertArrayEquals(new String[]{"TLSv1.1"}, sslContextBuilder.getSupportedProtocols());

        sslContextBuilder.setSupportedProtocols(new String[]{"TLSv1.1", "TLSv1.2"});
        assertArrayEquals(new String[]{"TLSv1.1", "TLSv1.2"}, sslContextBuilder.getSupportedProtocols());
    }

    @Test
    void testDefaultClientAuthentication() {
        final SslContextBuilder sslContextBuilder = createSslContextBuilder();
        assertThat(sslContextBuilder.getClientAuthentication(), is(SslClientAuthentication.NONE));
    }

    @Test
    void testSslClientAuthenticationToClientAuth() {
        assertThat(SslClientAuthentication.REQUIRED.toClientAuth(), is(ClientAuth.REQUIRE));
        assertThat(SslClientAuthentication.OPTIONAL.toClientAuth(), is(ClientAuth.OPTIONAL));
        assertThat(SslClientAuthentication.NONE.toClientAuth(), is(ClientAuth.NONE));
    }

    @Test
    void testBuildContextWithNonEncryptedKey() {
        final SslContextBuilder sslContextBuilder = new SslContextBuilder(CERTIFICATE, KEY, null);
        assertDoesNotThrow(sslContextBuilder::buildContext);
    }

    @Test
    void testBuildContextWithEncryptedKey() {
        final SslContextBuilder sslContextBuilder = new SslContextBuilder(CERTIFICATE, KEY_ENCRYPTED, "1234");
        assertDoesNotThrow(sslContextBuilder::buildContext);
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsRequired() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslContextBuilder()
                .setClientAuthentication(SslClientAuthentication.REQUIRED)
        );

        assertTrue(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsOptional() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslContextBuilder()
                .setClientAuthentication(SslClientAuthentication.OPTIONAL)
        );

        assertFalse(sslEngine.getNeedClientAuth());
        assertTrue(sslEngine.getWantClientAuth());
    }

    @Test
    void testBuildContextWhenClientAuthenticationIsNone() throws Exception {
        final SSLEngine sslEngine = assertSSlEngineFromBuilder(createSslContextBuilder()
                .setClientAuthentication(SslClientAuthentication.NONE));

        assertFalse(sslEngine.getNeedClientAuth());
        assertFalse(sslEngine.getWantClientAuth());
    }

    private SSLEngine assertSSlEngineFromBuilder(SslContextBuilder sslContextBuilder) throws Exception {
        final SslContext context = sslContextBuilder.buildContext();
        assertTrue(context.isServer());

        final SSLEngine sslEngine = context.newEngine(ByteBufAllocator.DEFAULT);

        if (sslContextBuilder.getCipherSuites().length > 0) {
            assertThat(sslEngine.getEnabledCipherSuites(), equalTo(sslContextBuilder.getCipherSuites()));
        }

        if (sslContextBuilder.getSupportedProtocols().length > 0) {
            assertThat(sslEngine.getEnabledProtocols(), equalTo(sslContextBuilder.getSupportedProtocols()));
        }

        return sslEngine;
    }

    private SslContextBuilder createSslContextBuilder() {
        return new SslContextBuilder(CERTIFICATE, KEY_ENCRYPTED, KEY_ENCRYPTED_PASS);
    }
}