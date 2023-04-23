package tech.httptoolkit.android.vpn.socket;

import cn.hutool.core.io.IoUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.httptoolkit.android.vpn.ClientPacketWriter;
import tech.httptoolkit.android.vpn.Session;
import tech.httptoolkit.android.vpn.transport.ip.IPv4Header;
import tech.httptoolkit.android.vpn.transport.tcp.TCPHeader;
import tech.httptoolkit.android.vpn.transport.tcp.TCPPacketFactory;
import tech.httptoolkit.android.vpn.transport.udp.UDPPacketFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;

/**
 * Takes a session, and reads all available upstream data back into it.
 * <br/>
 * Used by the NIO thread, and run synchronously as part of that non-blocking loop.
 */
class SocketChannelReader {

	private static final Logger log = LoggerFactory.getLogger(SocketChannelReader.class);

	private final ClientPacketWriter writer;

	public SocketChannelReader(ClientPacketWriter writer) {
		this.writer = writer;
	}

	public void read(Session session) {
		AbstractSelectableChannel channel = session.getChannel();

		if(channel instanceof SocketChannel) {
			readTCP(session);
		} else if(channel instanceof DatagramChannel){
			readUDP(session);
		} else {
			return;
		}

		// Resubscribe to reads, so that we're triggered again if more data arrives later.
		session.subscribeKey(SelectionKey.OP_READ);

		if (session.isAbortingConnection()) {
			log.debug("removing aborted connection -> {}", session);
			session.cancelKey();
			IoUtil.close(channel);
			session.closeSession();
		}
	}
	
	private void readTCP(Session session) {
		if (session.isAbortingConnection()) {
			return;
		}

		SocketChannel channel = (SocketChannel) session.getChannel();
		ByteBuffer buffer = ByteBuffer.allocate(DataConst.MAX_RECEIVE_BUFFER_SIZE);
		int len;

		try {
			do {
				len = channel.read(buffer);
				if (len > 0) { //-1 mean it reach the end of stream
					sendToRequester(buffer, len, session);
					buffer.clear();
				} else if (len == -1) {
					log.debug("End of data from remote server, will send FIN to client");
					log.debug("send FIN to: {}", session);
					sendFin(session);
					session.setAbortingConnection(true);
				}
			} while (len > 0);
		}catch(NotYetConnectedException e){
			log.error("socket not connected");
		}catch(ClosedByInterruptException e){
			log.debug("ClosedByInterruptException reading SocketChannel", e);
		}catch(ClosedChannelException e){
			log.error("ClosedChannelException reading SocketChannel", e);
		} catch (IOException e) {
			log.debug("Error reading data from SocketChannel", e);
			session.setAbortingConnection(true);
		}
	}
	
	private void sendToRequester(ByteBuffer buffer, int dataSize, Session session){
		// Last piece of data is usually smaller than MAX_RECEIVE_BUFFER_SIZE. We use this as a
		// trigger to set PSH on the resulting TCP packet that goes to the VPN.
		session.setHasReceivedLastSegment(dataSize < DataConst.MAX_RECEIVE_BUFFER_SIZE);

		buffer.limit(dataSize);
		buffer.flip();
		// TODO should allocate new byte array?
		byte[] data = new byte[dataSize];
		System.arraycopy(buffer.array(), 0, data, 0, dataSize);
		session.addReceivedData(data);
		//pushing all data to vpn client
		while(session.hasReceivedData()){
			pushDataToClient(session);
		}
	}
	/**
	 * create packet data and send it to VPN client
	 * @param session Session
	 */
	private void pushDataToClient(Session session){
		if (!session.hasReceivedData()) {
			//no data to send
			log.debug("no data for vpn client");
		}

		IPv4Header ipHeader = session.getLastIpHeader();
		TCPHeader tcpheader = session.getLastTcpHeader();
		// TODO What does 60 mean?
		int max = session.getMaxSegmentSize() - 60;

		if(max < 1) {
			max = 1024;
		}

		byte[] packetBody = session.getReceivedData(max);
		if(packetBody != null && packetBody.length > 0) {
			long unAck = session.getSendNext();
			long nextUnAck = session.getSendNext() + packetBody.length;
			session.setSendNext(nextUnAck);
			//we need this data later on for retransmission
			session.setUnackData(packetBody);
			session.setResendPacketCounter(0);

			byte[] data = TCPPacketFactory.createResponsePacketData(ipHeader,
					tcpheader, packetBody, session.hasReceivedLastSegment(),
					session.getRecSequence(), unAck,
					session.getTimestampSender(), session.getTimestampReplyto());

			writer.write(data);
		}
	}
	private void sendFin(Session session){
		final IPv4Header ipHeader = session.getLastIpHeader();
		final TCPHeader tcpheader = session.getLastTcpHeader();
		final byte[] data = TCPPacketFactory.createFinData(ipHeader, tcpheader,
				session.getRecSequence(), session.getSendNext(),
				session.getTimestampSender(), session.getTimestampReplyto());

		writer.write(data);
	}

	private void readUDP(Session session){
		DatagramChannel channel = (DatagramChannel) session.getChannel();
		ByteBuffer buffer = ByteBuffer.allocate(DataConst.MAX_RECEIVE_BUFFER_SIZE);
		int len;

		try {
			do{
				if (session.isAbortingConnection()) {
					break;
				}

				len = channel.read(buffer);
				if (len > 0) {
					buffer.limit(len);
					buffer.flip();

					//create UDP packet
					byte[] data = new byte[len];
					System.arraycopy(buffer.array(),0, data, 0, len);
					byte[] packetData = UDPPacketFactory.createResponsePacket(
							session.getLastIpHeader(), session.getLastUdpHeader(), data);

					//write to client
					writer.write(packetData);

					log.trace("SDR: sent {} bytes to UDP client, packetData.length: {}", len, packetData.length);
					buffer.clear();
				}
			} while(len > 0);
		}catch(NotYetConnectedException ex){
			log.error("failed to read from unconnected UDP socket");
		} catch (IOException e) {
			log.error("Failed to read from UDP socket, aborting connection");
			session.setAbortingConnection(true);
		}
	}
}
