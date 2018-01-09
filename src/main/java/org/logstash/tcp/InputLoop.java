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
import io.netty.handler.ssl.SslContext;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import org.apache.logging.log4j.Logger;

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
     * Reference to the logger.
     */
    private final Logger logger;

    /**
     * SSL configuration.
     */
    private final SslContext sslContext;

    /**
     * Ctor.
     * @param host Host to bind the listen to
     * @param port Port to listen on
     * @param decoder {@link Decoder} provided by Jruby
     */
    public InputLoop(final String host, final int port, final Decoder decoder,
                     final SslOptions sslOptions, final Logger logger) {

        // construct the SslContext now in order to validate the SSL options at startup rather
        // than client connection time
        if (sslOptions != null && sslOptions.isSslEnabled()) {
            try {
                sslContext = sslOptions.toSslContext();
            } catch (Exception e) {
                throw new RuntimeException("Error validating SSL configuration: " +
                        e.getMessage(), e);
            }
        } else {
            sslContext = null;
        }

        this.logger = logger;
        worker = new NioEventLoopGroup();
        boss = new NioEventLoopGroup(1);
        future = new ServerBootstrap().group(boss, worker)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 1024)
            .childHandler(new InputLoop.InputHandler(decoder, sslContext, logger)).bind(host, port);
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
         * SSL configuration options.
         */
        private final SslContext sslContext;

        /**
         * Reference to the logger.
         */
        private final Logger logger;

        /**
         * Ctor.
         * @param decoder {@link Decoder} provided by JRuby.
         */
        InputHandler(final Decoder decoder, final SslContext sslContext, Logger logger) {
            this.decoder = decoder;
            this.sslContext = sslContext;
            this.logger = logger;
        }

        @Override
        protected void initChannel(final SocketChannel channel) throws Exception {
            Decoder localCopy = decoder.copy();

            // if SSL is enabled, the SSL handler must be added to the pipeline first
            if (sslContext != null) {
                channel.pipeline().addLast(sslContext.newHandler(channel.alloc()));
            }

            channel.pipeline().addLast(new DecoderAdapter(localCopy, logger));
            channel.closeFuture().addListener(new FlushOnCloseListener(localCopy));
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            logger.error("Error in Netty input handler: " + cause);
            super.exceptionCaught(ctx, cause);
        }

        /**
         * Listeners that flushes the the JRuby supplied {@link Decoder} when the socket is closed.
         */
        private static final class FlushOnCloseListener implements GenericFutureListener<Future<Void>> {

            /**
             * {@link Decoder} supplied by JRuby.
             */
            private final Decoder decoder;

            /**
             * Ctor.
             * @param decoder {@link Decoder} provided by JRuby.
             */
            FlushOnCloseListener(Decoder decoder) { this.decoder = decoder; }

            @Override
            public void operationComplete(Future future) throws Exception {
                decoder.flush();
            }
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
             * Reference to the logger.
             */
            private final Logger logger;

            /**
             * Ctor.
             * @param decoder {@link Decoder} provided by JRuby.
             */
            DecoderAdapter(final Decoder decoder, Logger logger) {
                this.logger = logger;
                this.decoder = decoder;
            }

            @Override
            public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
                decoder.decode(ctx.channel().remoteAddress(), (ByteBuf) msg);
            }

            @Override
            public void exceptionCaught(final ChannelHandlerContext ctx, final Throwable cause) {
                logger.error("Error in Netty pipeline: " + cause);
                ctx.close();
            }
        }
    }
}
