package com.github.netguard.handler.session;

import org.krakenapps.pcap.util.Buffer;

import java.io.IOException;

/**
 * Decodes one TCP stream, created by {@link SessionFactory#createSession}.
 * <p>
 * Each direction has its own buffer. New bytes are appended to it, and the matching method is called
 * again as long as the buffer has unread bytes. Consume one complete frame and return <code>true</code>
 * to be called for the next one. If the rest is not a complete frame, move the read position back to
 * where the frame starts ({@link Buffer#mark()} / {@link Buffer#reset()}) and return <code>false</code>;
 * the method is called again when more bytes arrive. Bytes before the read position are discarded.
 * <p>
 * A {@link DecodeFailedException} is logged as a WARN by {@link SessionCreator}, and later bytes of the
 * stream are still passed to this session. The one exception is described on {@link #processTx}.
 *
 * @author zhkl0228
 */
public interface Session {
	
	/**
	 * Client to server.
	 * @return <code>true</code> after consuming a complete frame; <code>false</code> to wait for more bytes
	 * @throws DecodeFailedException the bytes cannot be decoded. If this happens on the first client bytes and a
	 * fallback was set with {@link SessionCreator#setFallbackTcpProcessor}, the stream is handed to that fallback
	 * from its first byte and this session gets nothing more. Sessions registered through
	 * <code>PacketDecoder.setSessionFactory</code> have no fallback.
	 */
	boolean processTx(Buffer buffer) throws IOException, DecodeFailedException;
	
	/**
	 * Server to client.
	 * @return <code>true</code> after consuming a complete frame; <code>false</code> to wait for more bytes
	 * @throws DecodeFailedException the bytes cannot be decoded; logged as a WARN, there is no fallback
	 */
	boolean processRx(Buffer buffer) throws IOException, DecodeFailedException;
	
	/**
	 * on tcp finish
	 */
	void onFinish();

}
