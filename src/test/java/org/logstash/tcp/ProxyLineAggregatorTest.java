package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.MatcherAssert.assertThat;
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
}
