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

import cn.hutool.core.io.IoUtil;
import com.github.netguard.vpn.PortRedirector;
import eu.faircode.netguard.Allowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tech.httptoolkit.android.vpn.socket.DataConst;
import tech.httptoolkit.android.vpn.socket.ICloseSession;
import tech.httptoolkit.android.vpn.util.PacketUtil;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manage in-memory storage for VPN client session.
 * @author Borey Sao
 * Date: May 20, 2014
 */
public class SessionManager implements ICloseSession {

	private static final Logger log = LoggerFactory.getLogger(SessionManager.class);

	private final Map<String, Session> table = new ConcurrentHashMap<>();

	private final PortRedirector portRedirector;

	public SessionManager(PortRedirector portRedirector) {
		this.portRedirector = portRedirector;
	}

	/**
	 * keep java garbage collector from collecting a session
	 * @param session Session
	 */
	public void keepSessionAlive(Session session) {
		if(session != null){
			String key = Session.getSessionKey(session.getDestIp(), session.getDestPort(),
					session.getSourceIp(), session.getSourcePort());
			table.put(key, session);
		}
	}

	/**
	 * add data from client which will be sending to the destination server later one when receiving PSH flag.
	 * @param buffer Data
	 * @param session Data
	 */
	public int addClientData(ByteBuffer buffer, Session session) {
		if (buffer.limit() <= buffer.position())
			return 0;
		//appending data to buffer
		return session.setSendingData(buffer);
	}

	public Session getSession(int ip, int port, int srcIp, int srcPort) {
		String key = Session.getSessionKey(ip, port, srcIp, srcPort);

		return getSessionByKey(key);
	}

	public Session getSessionByKey(String key) {
		if (table.containsKey(key)) {
			return table.get(key);
		}

		return null;
	}

	/**
	 * remove session from memory, then close socket connection.
	 * @param ip Destination IP Address
	 * @param port Destination Port
	 * @param srcIp Source IP Address
	 * @param srcPort Source Port
	 */
	public void closeSession(int ip, int port, int srcIp, int srcPort){
		String key = Session.getSessionKey(ip, port, srcIp, srcPort);
		Session session = table.remove(key);

		if(session != null){
			AbstractSelectableChannel channel = session.getChannel();
			IoUtil.close(channel);
			log.debug("closed session -> {}", key);
		}
	}

	public void closeSession(Session session){
		closeSession(session.getDestIp(),
				session.getDestPort(), session.getSourceIp(),
				session.getSourcePort());
	}

	public Session createNewUDPSession(int ip, int port, int srcIp, int srcPort) throws IOException {
		String keys = Session.getSessionKey(ip, port, srcIp, srcPort);

		// For TCP, we freak out if you try to create an already existing session.
		// With UDP though, it's totally fine:
		Session existingSession = table.get(keys);
		if (existingSession != null) return existingSession;

		Session session = new Session(srcIp, srcPort, ip, port, this);

		DatagramChannel channel;

		channel = DatagramChannel.open();
		channel.socket().setSoTimeout(0);
		channel.configureBlocking(false);

		session.setChannel(channel);

		// Initiate connection early to reduce latency
		String ips = PacketUtil.intToIPAddress(ip);
		String sourceIpAddress = PacketUtil.intToIPAddress(srcIp);
		Allowed redirect = portRedirector.redirectUdp(sourceIpAddress, srcPort, ips, port);
		final InetSocketAddress socketAddress;
		if (redirect == null) {
			socketAddress = new InetSocketAddress(ips, port);
		} else {
			socketAddress = new InetSocketAddress(redirect.raddr, redirect.rport);
		}
		log.debug("initialized connection to remote UDP server: {}:{} from {}:{}", ips, port, sourceIpAddress, srcPort);

		channel.connect(socketAddress);
		session.setConnected(channel.isConnected());

		table.put(keys, session);

		log.debug("new UDP session successfully created.");
		return session;
	}

	public Session createNewTCPSession(int ip, int port, int srcIp, int srcPort) throws IOException {
		String key = Session.getSessionKey(ip, port, srcIp, srcPort);

		Session existingSession = table.get(key);

		// This can happen if we receive two SYN packets somehow. That shouldn't happen,
		// given that our connection is local & should be 100% reliable, but it can.
		// We return the initialized session, which will be reacked to indicate rejection.
		if (existingSession != null) return existingSession;

		Session session = new Session(srcIp, srcPort, ip, port, this);

		SocketChannel channel;
		channel = SocketChannel.open();
		channel.socket().setKeepAlive(true);
		channel.socket().setTcpNoDelay(true);
		channel.socket().setSoTimeout(0);
		channel.socket().setReceiveBufferSize(DataConst.MAX_RECEIVE_BUFFER_SIZE);
		channel.configureBlocking(false);

		String ips = PacketUtil.intToIPAddress(ip);
		String srcIps = PacketUtil.intToIPAddress(srcIp);
		log.debug("created new SocketChannel for {}", key);

		log.debug("Protected new SocketChannel");

		session.setChannel(channel);

		// Initiate connection straight away, to reduce latency
		// We use the real address, unless tcpPortRedirection redirects us to a different
		// target address for traffic on this port.
		Allowed redirect = portRedirector.redirectTcp(srcIps, srcPort, ips, port);
		final InetSocketAddress socketAddress;
		if (redirect == null) {
			socketAddress = new InetSocketAddress(ips, port);
		} else {
			socketAddress = new InetSocketAddress(redirect.raddr, redirect.rport);
		}

		log.debug("Initiate connecting to remote tcp server: {}", socketAddress);
		boolean connected = channel.connect(socketAddress);
		session.setConnected(connected);

		table.put(key, session);

		return session;
	}
}
