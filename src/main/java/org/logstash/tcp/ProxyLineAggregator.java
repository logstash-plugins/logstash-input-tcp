package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.util.List;


/**
 * The line has format "PROXY....\r\n"; this aggregator holds back the buffer until that full
 * line is available, then passes it through and removes itself from the pipeline.
 * This is needed because Ruby class DecoderImpl expects the full line when processing the HAProxy
 * protocol and doesn't work with fragments.
 * */
public class ProxyLineAggregator extends ByteToMessageDecoder {

    private static final byte[] PROXY_PREFIX = "PROXY".getBytes(StandardCharsets.US_ASCII);
    public static final int PROXY_LENGTH = PROXY_PREFIX.length;

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out) throws Exception {
        // Wait until we can decide: enough bytes to match the prefix, and if it is a PROXY
        // line, the terminating \r\n must be present.
        if (buffer.readableBytes() < PROXY_LENGTH) {
            return;
        }
        if (startsWithProxy(buffer) && !containsCrlf(buffer)) {
            return;
        }
        // Full PROXY line, or non-PROXY data: pass everything through and drop this handler
        // so subsequent reads skip the aggregator entirely.
        out.add(buffer.readRetainedSlice(buffer.readableBytes()));
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
