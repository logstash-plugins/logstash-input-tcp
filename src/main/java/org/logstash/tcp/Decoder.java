package org.logstash.tcp;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;

/**
 * Decoder bridge to implement in JRuby.
 */
public interface Decoder {

    /**
     * Decode data coming from specific {@link SocketAddress} session.
     * @param key {@link SocketAddress}
     * @param message Data {@link ByteBuf} for this address
     */
    void decode(ChannelHandlerContext context, ByteBuf message);

    /**
     * Creates a copy of this decoder, that has all internal meta data cleared.
     */
    Decoder copy();

    /**
     * Flushes any data held in this decoder.
     */
    void flush();
}
