package org.logstash.tcp;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import java.io.Closeable;

/**
 * Plain TCP Server Implementation.
 */
public final class InputLoop implements Runnable, Closeable {

    /**
     * Netty Boss Group.
     */
    private final EventLoopGroup boss;

    /**
     * Netty Worker Group.
     */
    private final EventLoopGroup worker;

    /**
     * The Server Socket's {@link ChannelFuture}.
     */
    private final ChannelFuture future;

    /**
     * Ctor.
     * @param host Host to bind the listen to
     * @param port Port to listen on
     * @param decoder {@link Decoder} provided by Jruby
     */
    public InputLoop(final String host, final int port, final Decoder decoder) {
        worker = new NioEventLoopGroup();
        boss = new NioEventLoopGroup(1);
        future = new ServerBootstrap().group(boss, worker)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 1024)
            .childHandler(new InputLoop.InputHandler(decoder)).bind(host, port);
    }

    @Override
    public void run() {
        try {
            future.sync().channel().closeFuture().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void close() {
        try {
            worker.shutdownGracefully().sync();
            boss.shutdownGracefully().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * {@link ChannelInitializer} configuring client channels to forward all data to given
     * {@link Decoder}.
     */
    private static final class InputHandler extends ChannelInitializer<SocketChannel> {

        /**
         * {@link Decoder} supplied by JRuby.
         */
        private final Decoder decoder;

        /**
         * Ctor.
         * @param decoder {@link Decoder} provided by JRuby.
         */
        InputHandler(final Decoder decoder) {
            this.decoder = decoder;
        }

        @Override
        protected void initChannel(final SocketChannel channel) throws Exception {
            channel.pipeline().addLast(new InputLoop.InputHandler.DecoderAdapter(decoder.copy()));
        }

        /**
         * Adapter that wraps the JRuby supplied {@link Decoder}.
         */
        private static final class DecoderAdapter extends ChannelInboundHandlerAdapter {

            /**
             * {@link Decoder} provided by JRuby.
             */
            private final Decoder decoder;

            /**
             * Ctor.
             * @param decoder {@link Decoder} provided by JRuby.
             */
            DecoderAdapter(final Decoder decoder) {
                this.decoder = decoder;
            }

            @Override
            public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
                decoder.decode(ctx.channel().remoteAddress(), (ByteBuf) msg);
            }

            @Override
            public void exceptionCaught(final ChannelHandlerContext ctx,
                final Throwable cause) {
                ctx.close();
            }
        }
    }
}
