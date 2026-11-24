package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

class ProxyLineAggregatorTest {

    private EmbeddedChannel channel;

    @BeforeEach
    void setUp() {
        channel = new EmbeddedChannel(new ProxyLineAggregator());
    }

    @AfterEach
    void tearDown() {
        channel.finishAndReleaseAll();
    }

    private static ByteBuf ascii(String s) {
        return Unpooled.copiedBuffer(s, StandardCharsets.US_ASCII);
    }

    @Test
    void partialProxyHeader_producesNoOutput() {
        // "PRO" is shorter than the 5-byte "PROXY" prefix — decoder must wait
        channel.writeInbound(ascii("PRO"));
        assertThat(channel.readInbound(), nullValue());
    }

    @Test
    void proxyPrefixWithoutCRLF_producesNoOutput() {
        // Full PROXY keyword is present but the line terminator \r\n is missing
        channel.writeInbound(ascii("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80"));
        assertThat(channel.readInbound(), nullValue());
    }

    @Test
    void nonProxyDataWithSufficientBytes_passesThrough() {
        // Content >= PROXY_LENGTH bytes but not a PROXY header and no \r\n:
        // the aggregator should recognise it is not a PROXY line and let it through
        channel.writeInbound(ascii("Hello, World!"));
        ByteBuf result = channel.readInbound();
        assertThat(result, notNullValue());
        result.release();
    }

    @Test
    void completeProxyLineWithCRLF_forwardsBuffer() {
        channel.writeInbound(ascii("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80\r\n"));
        ByteBuf result = channel.readInbound();
        assertThat(result, notNullValue());
        result.release();
    }

    @Test
    void extractLine_storesProxyLineAndForwardsOnlyTheRest() {
        EmbeddedChannel tls = new EmbeddedChannel(new ProxyLineAggregator(true));
        try {
            // the PROXY line and the first bytes of the TLS handshake arrive in the same read
            tls.writeInbound(ascii("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80\r\n\u0016\u0003\u0001"));
            assertThat(tls.attr(ProxyLineAggregator.PROXY_LINE).get(), equalTo("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80"));
            ByteBuf result = tls.readInbound();
            assertThat(result.toString(StandardCharsets.US_ASCII), equalTo("\u0016\u0003\u0001"));
            result.release();
            assertThat(tls.pipeline().get(ProxyLineAggregator.class), nullValue());
        } finally {
            tls.finishAndReleaseAll();
        }
    }

    @Test
    void extractLine_waitsForSplitProxyLine() {
        EmbeddedChannel tls = new EmbeddedChannel(new ProxyLineAggregator(true));
        try {
            tls.writeInbound(ascii("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80\r"));
            assertThat(tls.readInbound(), nullValue());
            assertThat(tls.attr(ProxyLineAggregator.PROXY_LINE).get(), nullValue());
            tls.writeInbound(ascii("\n"));
            // only the line arrived: it is stored and nothing is forwarded
            assertThat(tls.attr(ProxyLineAggregator.PROXY_LINE).get(), equalTo("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80"));
            assertThat(tls.readInbound(), nullValue());
            assertThat(tls.pipeline().get(ProxyLineAggregator.class), nullValue());
            // later reads go straight through
            tls.writeInbound(ascii("\u0016\u0003\u0001"));
            ByteBuf result = tls.readInbound();
            assertThat(result.toString(StandardCharsets.US_ASCII), equalTo("\u0016\u0003\u0001"));
            result.release();
        } finally {
            tls.finishAndReleaseAll();
        }
    }

    @Test
    void extractLine_passesNonProxyDataThroughUnchanged() {
        EmbeddedChannel tls = new EmbeddedChannel(new ProxyLineAggregator(true));
        try {
            tls.writeInbound(ascii("\u0016\u0003\u0001\u0002\u0000"));
            assertThat(tls.attr(ProxyLineAggregator.PROXY_LINE).get(), nullValue());
            ByteBuf result = tls.readInbound();
            assertThat(result.toString(StandardCharsets.US_ASCII), equalTo("\u0016\u0003\u0001\u0002\u0000"));
            result.release();
        } finally {
            tls.finishAndReleaseAll();
        }
    }

    @Test
    void passThrough_doesNotSetTheProxyLineAttribute() {
        channel.writeInbound(ascii("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80\r\nhello"));
        assertThat(channel.attr(ProxyLineAggregator.PROXY_LINE).get(), nullValue());
        ByteBuf result = channel.readInbound();
        assertThat(result.toString(StandardCharsets.US_ASCII), equalTo("PROXY TCP4 192.168.1.1 10.0.0.1 1234 80\r\nhello"));
        result.release();
    }
}
