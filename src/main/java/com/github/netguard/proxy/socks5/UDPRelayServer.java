/*
 * Copyright 2015-2025 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.github.netguard.proxy.socks5;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;

/**
 * The class <code>UDPRelayServer</code> represents a UDP relay server.
 * <p>
 * The UDP relay server will receive datagram packets from a client and transmit them to the
 * specified server. It will also receive datagram packets from other UDP servers and send them to
 * client. UDP relay server must need to know the client's IP address and port to find out where the
 * datagram packet from, because UDP is not long connection protocol.
 * </p>
 *
 * @author Youchao Feng
 * @version 1.0
 * @date Apr 22, 2015 12:54:50 AM
 */
public class UDPRelayServer implements Runnable {

  /**
   * Logger that subclasses also can use.
   */
  protected static final Logger logger = LoggerFactory.getLogger(UDPRelayServer.class);

  /**
   * SOCKS5 datagram packet handle.
   */
  private final Socks5DatagramPacketHandler datagramPacketHandler = new Socks5DatagramPacketHandler();

  /**
   * UDP server.
   */
  private DatagramSocket server;

    /**
   * Running thread.
   */
  private Thread thread;

  /**
   * A status flag.
   */
  private boolean running;

  /**
   * Client's IP address.
   */
  private final InetSocketAddress clientSocketAddress;
  private final InetSocketAddress serverSocketAddress;

  /**
   * Constructs a {@link UDPRelayServer} instance with client's IP address and port. The UDP relay
   * server will use client's IP and port to find out where the datagram packet from.
   */
  public UDPRelayServer(InetSocketAddress clientSocketAddress, InetSocketAddress serverSocketAddress) {
    this.clientSocketAddress = clientSocketAddress;
    this.serverSocketAddress = serverSocketAddress;
    logger.debug("UDPRelayServer created: clientSocketAddress={}, serverSocketAddress={}", clientSocketAddress, serverSocketAddress);
  }

  /**
   * Starts a UDP relay server.
   *
   * @return Server bind socket address.
   * @throws SocketException If a SOCKS protocol error occurred.
   */
  public SocketAddress start() throws SocketException {
    running = true;
    if (logger.isDebugEnabled()) {
      server = new DatagramSocket(20270);
    } else {
      server = new DatagramSocket();
    }
    SocketAddress socketAddress = server.getLocalSocketAddress();
    thread = new Thread(this);
    thread.setDaemon(true);
    thread.start();
    return socketAddress;
  }

  /**
   * Stop the UDP relay server.
   */
  public void stop() {
    if (running) {
      running = false;
      if (thread != null) {
        thread.interrupt();
      }
      if (server != null && !server.isClosed()) {
        server.close();
      }
    }
  }

  @Override
  public void run() {
    try {
        int bufferSize = 1024 * 1024 * 5;
        byte[] buffer = new byte[bufferSize];
        InetSocketAddress lastClientSocketAddress = null;
      while (running) {
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
        server.receive(packet);
        boolean fromClient = isFromClient(packet);
        logger.debug("UDP relay server received packet [{}], fromClient={}", packet.getSocketAddress(), fromClient);
        if (fromClient) {
          lastClientSocketAddress = (InetSocketAddress) packet.getSocketAddress();
          datagramPacketHandler.decapsulate(packet);
          logger.debug("send from client packet [{}]", packet.getSocketAddress());
          server.send(packet);
        } else {
          packet = datagramPacketHandler.encapsulate(packet, logger.isDebugEnabled() ? lastClientSocketAddress : clientSocketAddress);
          logger.debug("send from server packet [{}]", packet.getSocketAddress());
          server.send(packet);
        }
      }
    } catch (IOException e) {
      if (e.getMessage().equalsIgnoreCase("Socket closed") && !running) {
        logger.debug("UDP relay server stopped");
      } else {
        logger.error(e.getMessage(), e);
      }
    }
  }

  /**
   * Returns <code>true</code> if the datagram packet from client.
   *
   * @param packet Datagram packet the UDP server received.
   * @return If the datagram packet is sent from client, it will return <code>true</code>.
   */
  protected boolean isFromClient(DatagramPacket packet) {
    if (logger.isDebugEnabled()) {
      if (packet.getAddress().getHostAddress().startsWith("127.")) {
        return true;
      }
    }
    if (clientSocketAddress.equals(packet.getSocketAddress())) {
      return true;
    }
    return !serverSocketAddress.equals(packet.getSocketAddress());
  }
}
