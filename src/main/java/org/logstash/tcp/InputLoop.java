package org.logstash.tcp;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * Plain TCP Server Implementation.
 */
public final class InputLoop implements Runnable, Closeable {

    // historically this class was passing around the plugin's logger
    private static final Logger logger = LogManager.getLogger("logstash.inputs.tcp");

    /**
     * Netty Boss Group.
     */
    private final EventLoopGroup boss;

    /**
     * Netty Worker Group.
     */
    private final EventLoopGroup worker;

    /**
     * The Server Bootstrap
     */
    private final ServerBootstrap serverBootstrap;

    /**
     * SSL configuration.
     */
    private final SslContext sslContext;

    /**
     * TCP Port.
     */
    private final int port;

    /**
     * TCP Host.
     */
    private final String host;

    /**
     * Ctor.
     * @param host Host to bind the listen to
     * @param port Port to listen on
     * @param decoder {@link Decoder} provided by Jruby
     * @param keepAlive set to true to instruct the socket to issue TCP keep alive
     */
    public InputLoop(final String host, final int port, final Decoder decoder, final boolean keepAlive,
                     final SslContext sslContext) {
        this.sslContext = sslContext;
        this.host = host;
        this.port = port;
        worker = new NioEventLoopGroup();
        boss = new NioEventLoopGroup(1);
        serverBootstrap = new ServerBootstrap().group(boss, worker)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 1024)
            .childOption(ChannelOption.SO_KEEPALIVE, keepAlive)
            .childHandler(new InputLoop.InputHandler(decoder, sslContext));
    }

    @Override
    public void run() {
        try {
            serverBootstrap.bind(host, port).sync().channel().closeFuture().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public void close() {
        try {
            // Shut down boss first otherwise new connections
            // will be passed to a closed worker loop, triggering:
            // RejectedExecutionException: event executor terminated
            boss.shutdownGracefully().sync();
            worker.shutdownGracefully().sync();
        } catch (final InterruptedException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * {@link ChannelInitializer} configuring client channels to forward all data to given
     * {@link Decoder}.
     */
    private static final class InputHandler extends ChannelInitializer<SocketChannel> {
        private final String SSL_HANDLER = "ssl-handler";

        /**
         * {@link Decoder} supplied by JRuby.
         */
        private final Decoder decoder;

        /**
         * SSL configuration options.
         */
        private final SslContext sslContext;

        /**
         * Ctor.
         * @param decoder {@link Decoder} provided by JRuby.
         */
        InputHandler(final Decoder decoder, final SslContext sslContext) {
            this.decoder = decoder;
            this.sslContext = sslContext;
        }

        @Override
        protected void initChannel(final SocketChannel channel) throws Exception {
            Decoder localCopy = decoder.copy();

            // if SSL is enabled, the SSL handler must be added to the pipeline first
            if (sslContext != null) {
                channel.pipeline().addLast(SSL_HANDLER, sslContext.newHandler(channel.alloc()));
            }

            channel.pipeline().addLast(new DecoderAdapter(localCopy, logger));
            channel.closeFuture().addListener(new FlushOnCloseListener(localCopy));

            if (logger.isDebugEnabled()) {
                logger.debug(remoteChannelInfo(channel) + ": initialized channel");
            }
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

            // 6.07 updated to pass in the full netty ChannelHandlerContext instead of the remoteaddress field
            //      corresponding interface updated
            @Override
            public void channelRead(final ChannelHandlerContext ctx, final Object msg) {
                decoder.decode(ctx, (ByteBuf) msg);
            }

            @Override
            public void exceptionCaught(final ChannelHandlerContext ctx, final Throwable cause) {
                final String channelInfo = remoteChannelInfo(ctx.channel());
                if (silentException(cause)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(channelInfo + ": closing", cause);
                    } else {
                        logger.info("{}: closing ({})", channelInfo, cause.getMessage());
                    }
                } else {
                    logger.error(channelInfo + ": closing due:", cause);
                }
                ctx.close();
            }

            private boolean silentException(final Throwable ex) {
                if (ex instanceof IOException) {
                    return ex.getMessage() != null && ex.getMessage().contains("Connection reset");
                }
                return false;
            }
        }
    }

    private static String remoteChannelInfo(final Channel channel) {
        final InetSocketAddress remote = ((InetSocketAddress) channel.remoteAddress());
        if (remote != null) {
            return remote.getAddress() + ":" + remote.getPort();
        }
        return null;
    }
}
