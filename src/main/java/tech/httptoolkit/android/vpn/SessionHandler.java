/*
 *  Copyright 2014 AT&T
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

package tech.httptoolkit.android.vpn;

import com.github.netguard.vpn.IPacketCapture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.httptoolkit.android.vpn.socket.SocketNIODataService;
import tech.httptoolkit.android.vpn.transport.PacketHeaderException;
import tech.httptoolkit.android.vpn.transport.icmp.ICMPPacket;
import tech.httptoolkit.android.vpn.transport.icmp.ICMPPacketFactory;
import tech.httptoolkit.android.vpn.transport.ip.IPPacketFactory;
import tech.httptoolkit.android.vpn.transport.ip.IPv4Header;
import tech.httptoolkit.android.vpn.transport.tcp.TCPHeader;
import tech.httptoolkit.android.vpn.transport.tcp.TCPPacketFactory;
import tech.httptoolkit.android.vpn.transport.udp.UDPHeader;
import tech.httptoolkit.android.vpn.transport.udp.UDPPacketFactory;
import tech.httptoolkit.android.vpn.util.PacketUtil;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.util.concurrent.ExecutorService;

/**
 * handle VPN client request and response. it create a new session for each VPN client.
 * @author Borey Sao
 * Date: May 22, 2014
 */
public class SessionHandler {

	private static final Logger log = LoggerFactory.getLogger(SessionHandler.class);

	private final SessionManager manager;
	private final SocketNIODataService nioService;
	private final ClientPacketWriter writer;
	private final ExecutorService pingThreadPool;
	private final IPacketCapture packetCapture;

	public SessionHandler(SessionManager manager, SocketNIODataService nioService, ClientPacketWriter writer, ExecutorService pingThreadPool, IPacketCapture packetCapture) {
		this.manager = manager;
		this.nioService = nioService;
		this.writer = writer;
		this.pingThreadPool = pingThreadPool;
		this.packetCapture = packetCapture;
	}

	/**
	 * Handle unknown raw IP packet data
	 *
	 * @param stream ByteBuffer to be read
	 */
	public void handlePacket(ByteBuffer stream) throws PacketHeaderException, IOException {
		final byte[] rawPacket = new byte[stream.limit()];
		stream.get(rawPacket, 0, stream.limit());
		stream.rewind();

		final IPv4Header ipHeader = IPPacketFactory.createIPv4Header(stream);

		boolean handled = false;
		if (ipHeader.getProtocol() == 6) {
			handleTCPPacket(stream, ipHeader);
			handled = true;
		} else if (ipHeader.getProtocol() == 17) {
			handleUDPPacket(stream, ipHeader);
			handled = true;
		} else if (ipHeader.getProtocol() == 1) {
			handleICMPPacket(stream, ipHeader);
			handled = true;
		} else {
			log.warn("Unsupported IP protocol: {}", ipHeader.getProtocol());
		}
		if (handled && packetCapture != null) {
			packetCapture.onPacket(rawPacket, "ToyShark");
		}
	}

	private void handleUDPPacket(ByteBuffer clientPacketData, IPv4Header ipHeader) throws PacketHeaderException, IOException {
		UDPHeader udpheader = UDPPacketFactory.createUDPHeader(clientPacketData);

		Session session = manager.getSession(
			ipHeader.getDestinationIP(), udpheader.getDestinationPort(),
			ipHeader.getSourceIP(), udpheader.getSourcePort()
		);

		boolean newSession = session == null;

		if (session == null) {
			session = manager.createNewUDPSession(
				ipHeader.getDestinationIP(), udpheader.getDestinationPort(),
				ipHeader.getSourceIP(), udpheader.getSourcePort()
			);
		}

		synchronized (session) {
			session.setLastIpHeader(ipHeader);
			session.setLastUdpHeader(udpheader);
			manager.addClientData(clientPacketData, session);
			session.setDataForSendingReady(true);

			// We don't register the session until it's fully populated (as above)
			if (newSession) nioService.registerSession(session);

			// Ping the NIO thread to write this, when the session is next writable
			session.subscribeKey(SelectionKey.OP_WRITE);
			nioService.refreshSelect(session);
		}

		manager.keepSessionAlive(session);
	}

	private void handleTCPPacket(ByteBuffer clientPacketData, IPv4Header ipHeader) throws PacketHeaderException, IOException {
		TCPHeader tcpheader = TCPPacketFactory.createTCPHeader(clientPacketData);
		int dataLength = clientPacketData.limit() - clientPacketData.position();
		int sourceIP = ipHeader.getSourceIP();
		int destinationIP = ipHeader.getDestinationIP();
		int sourcePort = tcpheader.getSourcePort();
		int destinationPort = tcpheader.getDestinationPort();

		if (tcpheader.isSYN()) {
			// 3-way handshake + create new session
			replySynAck(ipHeader,tcpheader);
		} else if(tcpheader.isACK()) {
			String key = Session.getSessionKey(destinationIP, destinationPort, sourceIP, sourcePort);
			Session session = manager.getSessionByKey(key);

			if (session == null) {
				log.debug("Ack for unknown session: {}", key);
				if (tcpheader.isFIN()) {
					sendLastAck(ipHeader, tcpheader);
				} else if (!tcpheader.isRST()) {
					sendRstPacket(ipHeader, tcpheader, dataLength);
				}

				return;
			}

			synchronized (session) {
				session.setLastIpHeader(ipHeader);
				session.setLastTcpHeader(tcpheader);

				//any data from client?
				if (dataLength > 0) {
					//accumulate data from client
					if (session.getRecSequence() == 0 || tcpheader.getSequenceNumber() >= session.getRecSequence()) {
						int addedLength = manager.addClientData(clientPacketData, session);
						//send ack to client only if new data was added
						sendAck(ipHeader, tcpheader, addedLength, session);
					} else {
						sendAckForDisorder(ipHeader, tcpheader, dataLength);
					}
				} else {
					//an ack from client for previously sent data
					acceptAck(tcpheader, session);

					if (session.isClosingConnection()) {
						sendFinAck(ipHeader, tcpheader, session);
					} else if (session.isAckedToFin() && !tcpheader.isFIN()) {
						//the last ACK from client after FIN-ACK flag was sent
						manager.closeSession(destinationIP, destinationPort, sourceIP, sourcePort);
						log.debug("got last ACK after FIN, session is now closed.");
					}
				}
				//received the last segment of data from vpn client
				if (tcpheader.isPSH()) {
					// Tell the NIO thread to immediately send data to the destination
					pushDataToDestination(session, tcpheader);
				} else if (tcpheader.isFIN()) {
					//fin from vpn client is the last packet
					//ack it
					log.debug("FIN from vpn client, will ack it.");
					ackFinAck(ipHeader, tcpheader, session);
				} else if (tcpheader.isRST()) {
					resetConnection(ipHeader, tcpheader);
				}

				if (!session.isAbortingConnection()) {
					manager.keepSessionAlive(session);
				}
			}
		} else if(tcpheader.isFIN()){
			//case client sent FIN without ACK
			Session session = manager.getSession(destinationIP, destinationPort, sourceIP, sourcePort);
			if(session == null)
				ackFinAck(ipHeader, tcpheader, null);
			else
				manager.keepSessionAlive(session);

		} else if(tcpheader.isRST()){
			resetConnection(ipHeader, tcpheader);
		} else {
			log.debug("unknown TCP flag");
			String str1 = PacketUtil.getOutput(ipHeader, tcpheader, clientPacketData.array());
			log.debug(">>>>>>>> Received from client <<<<<<<<<<");
			log.debug(str1);
			log.debug(">>>>>>>>>>>>>>>>>>>end receiving from client>>>>>>>>>>>>>>>>>>>>>");
		}
	}

	private void sendRstPacket(IPv4Header ip, TCPHeader tcp, int dataLength){
		byte[] data = TCPPacketFactory.createRstData(ip, tcp, dataLength);

		writer.write(data);
		if (log.isDebugEnabled()) {
			log.debug("Sent RST Packet to client with dest => {}:{}", PacketUtil.intToIPAddress(ip.getDestinationIP()), tcp.getDestinationPort());
		}
	}

	private void sendLastAck(IPv4Header ip, TCPHeader tcp){
		byte[] data = TCPPacketFactory.createResponseAckData(ip, tcp, tcp.getSequenceNumber()+1);

		writer.write(data);
		if (log.isDebugEnabled()) {
			log.debug("Sent last ACK Packet to client with dest => {}:{}", PacketUtil.intToIPAddress(ip.getDestinationIP()), tcp.getDestinationPort());
		}
	}

	private void ackFinAck(IPv4Header ip, TCPHeader tcp, Session session){
		long ack = tcp.getSequenceNumber() + 1;
		long seq = tcp.getAckNumber();
		byte[] data = TCPPacketFactory.createFinAckData(ip, tcp, ack, seq, true, true);

		writer.write(data);
		if(session != null){
			session.cancelKey();
			manager.closeSession(session);
			if (log.isDebugEnabled()) {
				log.debug("ACK to client's FIN and close session => {}:{}-{}:{}", PacketUtil.intToIPAddress(ip.getDestinationIP()), tcp.getDestinationPort(), PacketUtil.intToIPAddress(ip.getSourceIP()), tcp.getSourcePort());
			}
		}
	}
	private void sendFinAck(IPv4Header ip, TCPHeader tcp, Session session){
		final long ack = tcp.getSequenceNumber();
		final long seq = tcp.getAckNumber();
		final byte[] data = TCPPacketFactory.createFinAckData(ip, tcp, ack, seq,true,false);
		final ByteBuffer stream = ByteBuffer.wrap(data);

		writer.write(data);
		log.debug("00000000000 FIN-ACK packet data to vpn client 000000000000");
		IPv4Header vpnip = null;
		try {
			vpnip = IPPacketFactory.createIPv4Header(stream);
		} catch (PacketHeaderException e) {
			e.printStackTrace(System.err);
		}

		TCPHeader vpntcp = null;
		try {
			if (vpnip != null)
				vpntcp = TCPPacketFactory.createTCPHeader(stream);
		} catch (PacketHeaderException e) {
			e.printStackTrace(System.err);
		}

		if(vpnip != null && vpntcp != null){
			if (log.isDebugEnabled()) {
				log.debug(PacketUtil.getOutput(vpnip, vpntcp, data));
			}
		}
		log.debug("0000000000000 finished sending FIN-ACK packet to vpn client 000000000000");

		session.setSendNext(seq + 1);
		//avoid re-sending it, from here client should take care the rest
		session.setClosingConnection(false);
	}

	private void pushDataToDestination(Session session, TCPHeader tcp){
		session.setDataForSendingReady(true);
		session.setTimestampReplyto(tcp.getTimeStampSender());
		session.setTimestampSender((int)System.currentTimeMillis());

		// Ping the NIO thread to write this, when the session is next writable
		session.subscribeKey(SelectionKey.OP_WRITE);
		nioService.refreshSelect(session);
	}
	
	/**
	 * send acknowledgment packet to VPN client
	 * @param ipheader IP Header
	 * @param tcpheader TCP Header
	 * @param acceptedDataLength Data Length
	 * @param session Session
	 */
	private void sendAck(IPv4Header ipheader, TCPHeader tcpheader, int acceptedDataLength, Session session){
		long acknumber = session.getRecSequence() + acceptedDataLength;
		session.setRecSequence(acknumber);
		byte[] data = TCPPacketFactory.createResponseAckData(ipheader, tcpheader, acknumber);

		writer.write(data);
	}

	/**
	 * resend the last acknowledgment packet to VPN client, e.g. when an unexpected out of order
	 * packet arrives.
	 * @param session Session
	 */
	private void resendAck(Session session){
		byte[] data = TCPPacketFactory.createResponseAckData(
				session.getLastIpHeader(),
				session.getLastTcpHeader(),
				session.getRecSequence()
		);
		writer.write(data);
	}

	private void sendAckForDisorder(IPv4Header ipHeader, TCPHeader tcpheader, int acceptedDataLength) {
		long ackNumber = tcpheader.getSequenceNumber() + acceptedDataLength;
		log.debug("sent disorder ack, ack# {} + {} = {}", tcpheader.getSequenceNumber(), acceptedDataLength, ackNumber);
		byte[] data = TCPPacketFactory.createResponseAckData(ipHeader, tcpheader, ackNumber);

		writer.write(data);
	}

	/**
	 * acknowledge a packet.
	 * @param tcpHeader TCP Header
	 * @param session Session
	 */
	private void acceptAck(TCPHeader tcpHeader, Session session){
		boolean isCorrupted = PacketUtil.isPacketCorrupted(tcpHeader);

		session.setPacketCorrupted(isCorrupted);
		if (isCorrupted) {
			log.debug("prev packet was corrupted, last ack# {}", tcpHeader.getAckNumber());
		}

		if (
			tcpHeader.getAckNumber() > session.getSendUnack() ||
			tcpHeader.getAckNumber() == session.getSendNext()
		) {
			session.setAcked(true);

			session.setSendUnack(tcpHeader.getAckNumber());
			session.setRecSequence(tcpHeader.getSequenceNumber());
			session.setTimestampReplyto(tcpHeader.getTimeStampSender());
			session.setTimestampSender((int) System.currentTimeMillis());
		} else {
			log.debug("Not Accepting ack# {} , it should be: {}", tcpHeader.getAckNumber(), session.getSendNext());
			log.debug("Prev sendUnack: {}", session.getSendUnack());
			session.setAcked(false);
		}
	}

	/**
	 * set connection as aborting so that background worker will close it.
	 * @param ip IP
	 * @param tcp TCP
	 */
	private void resetConnection(IPv4Header ip, TCPHeader tcp){
		Session session = manager.getSession(
			ip.getDestinationIP(), tcp.getDestinationPort(),
			ip.getSourceIP(), tcp.getSourcePort()
		);
		if(session != null){
			synchronized (session) {
				session.setAbortingConnection(true);
			}
		}
	}

	/**
	 * create a new client's session and SYN-ACK packet data to respond to client
	 * @param ip IP
	 * @param tcp TCP
	 */
	private void replySynAck(IPv4Header ip, TCPHeader tcp) throws IOException {
		ip.setIdentification(0);
		Packet packet = TCPPacketFactory.createSynAckPacketData(ip, tcp);
		
		TCPHeader tcpheader = (TCPHeader) packet.getTransportHeader();
		
		Session session = manager.createNewTCPSession(
			ip.getDestinationIP(), tcp.getDestinationPort(),
			ip.getSourceIP(), tcp.getSourcePort()
		);

		if (session.getLastIpHeader() != null) {
			// We have an existing session for this connection! We've somehow received a SYN
			// for an existing socket (or some kind of other race). We resend the last ACK
			// for this session, rejecting this SYN. Not clear why this happens, but it can.
			resendAck(session);
			return;
		}

		synchronized (session) {
			session.setMaxSegmentSize(tcpheader.getMaxSegmentSize());
			session.setSendUnack(tcpheader.getSequenceNumber());
			session.setSendNext(tcpheader.getSequenceNumber() + 1);
			//client initial sequence has been incremented by 1 and set to ack
			session.setRecSequence(tcpheader.getAckNumber());

			session.setLastIpHeader(ip);
			session.setLastTcpHeader(tcp);

			nioService.registerSession(session);

			writer.write(packet.getBuffer());
			log.debug("Send SYN-ACK to client");
		}
	}

	private void handleICMPPacket(
		ByteBuffer clientPacketData,
		final IPv4Header ipHeader
	) throws PacketHeaderException {
		final ICMPPacket requestPacket = ICMPPacketFactory.parseICMPPacket(clientPacketData);
		log.debug("Got an ICMP ping packet, type {}", requestPacket);

		if (requestPacket.type == ICMPPacket.DESTINATION_UNREACHABLE_TYPE) {
			// This is a packet from the phone, telling somebody that a destination is unreachable.
			// Might be caused by issues on our end, but it's unclear what kind of issues. Regardless,
			// we can't send ICMP messages ourselves or react usefully, so we drop these silently.
			return;
		} else if (requestPacket.type != ICMPPacket.ECHO_REQUEST_TYPE) {
			// We only actually support outgoing ping packets. Loudly drop anything else:
			throw new PacketHeaderException(
				"Unknown ICMP type (" + requestPacket.type + "). Only echo requests are supported"
			);
		}

		pingThreadPool.execute(new Runnable() {
			@Override
			public void run() {
				try {
					if (!isReachable(PacketUtil.intToIPAddress(ipHeader.getDestinationIP()))) {
						log.debug("Failed ping, ignoring");
						return;
					}

					ICMPPacket response = ICMPPacketFactory.buildSuccessPacket(requestPacket);

					// Flip the address
					int destination = ipHeader.getDestinationIP();
					int source = ipHeader.getSourceIP();
					ipHeader.setSourceIP(destination);
					ipHeader.setDestinationIP(source);

					byte[] responseData = ICMPPacketFactory.packetToBuffer(ipHeader, response);

					log.debug("Successful ping response");
					writer.write(responseData);
				} catch (PacketHeaderException e) {
					log.warn("Handling ICMP failed with", e);
				}
			}

			private boolean isReachable(String ipAddress) {
				try {
					return InetAddress.getByName(ipAddress).isReachable(10000);
				} catch (IOException e) {
					return false;
				}
			}
		});
	}
}
