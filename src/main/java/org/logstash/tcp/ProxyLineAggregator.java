package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.AttributeKey;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.util.List;


/**
 * The line has format "PROXY....\r\n"; this aggregator holds back the buffer until that full
 * line is available, then passes it through and removes itself from the pipeline.
 * This is needed because Ruby class DecoderImpl expects the full line when processing the HAProxy
 * protocol and doesn't work with fragments.
 * <p>
 * When TLS is enabled, the PROXY line arrives in clear text before the TLS handshake, so the
 * aggregator must sit in front of the SSL handler and must not pass the line on to it. In that
 * mode ({@code extractLine} set to true) it removes the line from the stream, stores it, without
 * the trailing \r\n, in the {@link #PROXY_LINE} channel attribute, and passes only the bytes that
 * follow it.
 * */
public class ProxyLineAggregator extends ByteToMessageDecoder {

    private static final byte[] PROXY_PREFIX = "PROXY".getBytes(StandardCharsets.US_ASCII);
    public static final int PROXY_LENGTH = PROXY_PREFIX.length;

    /**
     * Channel attribute that holds the PROXY line when it was extracted in front of the SSL handler.
     */
    public static final AttributeKey<String> PROXY_LINE = AttributeKey.valueOf("logstash.tcp.proxyLine");

    private final boolean extractLine;

    public ProxyLineAggregator() {
        this(false);
    }

    /**
     * @param extractLine true to remove the PROXY line from the stream and store it in the
     *                    {@link #PROXY_LINE} channel attribute, false to pass it through
     */
    public ProxyLineAggregator(final boolean extractLine) {
        this.extractLine = extractLine;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out) throws Exception {
        // Wait until we can decide: enough bytes to match the prefix, and if it is a PROXY
        // line, the terminating \r\n must be present.
        if (buffer.readableBytes() < PROXY_LENGTH) {
            return;
        }
        final boolean proxyLine = startsWithProxy(buffer);
        if (proxyLine && !containsCrlf(buffer)) {
            return;
        }
        if (proxyLine && extractLine) {
            final int lineLength = buffer.forEachByte(ByteProcessor.FIND_LF) - buffer.readerIndex() + 1;
            ctx.channel().attr(PROXY_LINE).set(buffer.toString(buffer.readerIndex(), lineLength - 2, StandardCharsets.US_ASCII));
            buffer.skipBytes(lineLength);
        }
        // Full PROXY line, or non-PROXY data: pass everything through and drop this handler
        // so subsequent reads skip the aggregator entirely.
        if (buffer.isReadable()) {
            out.add(buffer.readRetainedSlice(buffer.readableBytes()));
        }
        ctx.pipeline().remove(this);
    }

    private static boolean containsCrlf(ByteBuf buffer) {
        int lfIndex = buffer.forEachByte(ByteProcessor.FIND_LF);
        return lfIndex > 0 && buffer.getByte(lfIndex - 1) == '\r';
    }

    private static boolean startsWithProxy(ByteBuf buffer) {
        for (int i = 0; i < PROXY_LENGTH; i++) {
            if (buffer.getByte(buffer.readerIndex() + i) != PROXY_PREFIX[i]) {
                return false;
            }
        }
        return true;
    }
}
