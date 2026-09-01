package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.util.ByteProcessor;

import java.nio.charset.StandardCharsets;
import java.util.List;


/**
 * Accumulate bytes until the HAProxy format v1 headline is present in the buffer.
 * The line has format "PROXY....\r\n", this aggregator reject the buffer until it has that format,
 * once reached passthrough every buffer as it is.
 * This is needed because Ruby class DecoderImpl expect to have the full line when processing HAProxy protocol, and
 * doesn't work with fragments.
 * */
public class ProxyLineAggregator extends ByteToMessageDecoder {

    private static final byte[] PROXY_PREFIX = "PROXY".getBytes(StandardCharsets.US_ASCII);
    public static final int PROXY_LENGTH = PROXY_PREFIX.length;

    enum DecoderState {READ_PROXY, COMPLETED}

    private DecoderState state;

    public ProxyLineAggregator() {
        this.state = DecoderState.READ_PROXY;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out) throws Exception {
        switch (state) {
            case READ_PROXY:
                if (buffer.readableBytes() < PROXY_LENGTH) {
                    return;
                }
                if (!startsWithProxy(buffer)) {
                    state = DecoderState.COMPLETED;
                    out.add(buffer.readRetainedSlice(buffer.readableBytes()));
                    return;
                }
                if (buffer.forEachByte(ByteProcessor.FIND_CRLF) == -1) {
                    return;
                }
                state = DecoderState.COMPLETED;
                out.add(buffer.readRetainedSlice(buffer.readableBytes()));
                break;
            case COMPLETED:
                out.add(buffer.readRetainedSlice(buffer.readableBytes()));
                break;
        }
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
