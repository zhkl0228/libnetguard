package tech.httptoolkit.android.vpn.socket;

import cn.hutool.core.io.IoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.httptoolkit.android.vpn.ClientPacketWriter;
import tech.httptoolkit.android.vpn.Session;
import tech.httptoolkit.android.vpn.transport.tcp.TCPPacketFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.util.Date;

/**
 * Takes a VPN session, and writes all received data from it to the upstream channel.
 * <br/>
 * If any writes fail, it resubscribes to OP_WRITE, and tries again next time
 * that fires (as soon as the channel is ready for more data).
 * <br/>
 * Used by the NIO thread, and run synchronously as part of that non-blocking loop.
 */
public class SocketChannelWriter {

	private static final Logger log = LoggerFactory.getLogger(SocketChannelWriter.class);

	private final ClientPacketWriter writer;

	SocketChannelWriter(ClientPacketWriter writer) {
		this.writer = writer;
	}

	public void write(Session session) {
		AbstractSelectableChannel channel = session.getChannel();
		if (channel instanceof SocketChannel) {
			writeTCP(session);
		} else if(channel instanceof DatagramChannel) {
			writeUDP(session);
		} else {
			// We only ever create TCP & UDP channels, so this should never happen
			throw new IllegalArgumentException("Unexpected channel type: " + channel);
		}

		if (session.isAbortingConnection()) {
			log.debug("removing aborted connection -> {}", session);
			session.cancelKey();

			IoUtil.close(channel);
			session.closeSession();
		}
	}

	private void writeUDP(Session session) {
		try {
			writePendingData(session);
			Date dt = new Date();
			session.connectionStartTime = dt.getTime();
		}catch(NotYetConnectedException ex2){
			session.setAbortingConnection(true);
			log.error("Error writing to unconnected-UDP server, will abort current connection", ex2);
		} catch (IOException e) {
			session.setAbortingConnection(true);
			log.error("Error writing to UDP server, will abort connection", e);
		}
	}
	
	private void writeTCP(Session session) {
		try {
			writePendingData(session);
		} catch (NotYetConnectedException ex) {
			log.error("failed to write to unconnected socket", ex);
		} catch (IOException e) {
			log.error("Error writing to server", e);
			
			//close connection with vpn client
			byte[] rstData = TCPPacketFactory.createRstData(
					session.getLastIpHeader(), session.getLastTcpHeader(), 0);

			writer.write(rstData);

			//remove session
			log.error("failed to write to remote socket, aborting connection");
			session.setAbortingConnection(true);
		}
	}

	private void writePendingData(Session session) throws IOException {
		if (!session.hasDataToSend()) return;
		AbstractSelectableChannel channel = session.getChannel();

		byte[] data = session.getSendingData();
		ByteBuffer buffer = ByteBuffer.allocate(data.length);
		buffer.put(data);
		buffer.flip();

		while (buffer.hasRemaining()) {
			int bytesWritten = channel instanceof SocketChannel
				? ((SocketChannel) channel).write(buffer)
				: ((DatagramChannel) channel).write(buffer);

			if (bytesWritten == 0) {
				break;
			}
		}

		if (buffer.hasRemaining()) {
			// The channel's own buffer is full, so we have to save this for later.
			log.info("{} bytes unwritten for {}", buffer.remaining(), channel);

			// Put the remaining data from the buffer back into the session
			session.setSendingData(buffer.compact());

			// Subscribe to WRITE events, so we know when this is ready to resume.
			session.subscribeKey(SelectionKey.OP_WRITE);
		} else {
			// All done, all good -> wait until the next TCP PSH / UDP packet
			session.setDataForSendingReady(false);

			// We don't need to know about WRITE events any more, we've written all our data.
			// This is safe from races with new data, due to the session lock in NIO.
			session.unsubscribeKey(SelectionKey.OP_WRITE);
		}
	}
}
