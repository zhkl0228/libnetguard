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
import java.nio.ByteBuffer;

/**
 * The class <code>Socks5DatagramPacketHandler</code> represents a datagram packet handler.
 * <p>
 * This class can encapsulate a datagram packet or decapsulate a datagram packet.
 * </p>
 *
 * @author Youchao Feng
 * @version 1.0
 * @date Mar 24, 2015 9:09:39 PM
 */
public class Socks5DatagramPacketHandler implements DatagramPacketEncapsulation,
    DatagramPacketDecapsulation {

  /**
   * Logger that subclasses also can use.
   */
  protected static final Logger logger = LoggerFactory.getLogger(Socks5DatagramPacketHandler.class);

  public Socks5DatagramPacketHandler() {
  }


  /**
   * IP version 4 address.
   */
  private static final int IPV4 = 0x01;
  /**
   * Domain name.
   */
  private static final int DOMAIN_NAME = 0x03;

  /**
   * IP version 6 address.
   */
  private static final int IPV6 = 0x04;

  @Override
  public DatagramPacket encapsulate(DatagramPacket packet, SocketAddress destination) throws
          IOException {
    if (destination instanceof InetSocketAddress) {
      InetSocketAddress destinationAddress = (InetSocketAddress) destination;
      final byte[] data = packet.getData();
      final InetAddress remoteServerAddress = packet.getAddress();
      final byte[] addressBytes = remoteServerAddress.getAddress();
      final int ADDRESS_LENGTH = remoteServerAddress.getAddress().length;
      final int remoteServerPort = packet.getPort();
      ByteBuffer buffer = ByteBuffer.allocate(6 + packet.getLength() + ADDRESS_LENGTH);

      buffer.putShort((short) 0); // reserved byte
      buffer.put((byte) 0); // fragment byte
      buffer.put((byte) (ADDRESS_LENGTH == 4 ? IPV4 : IPV6));
      buffer.put(addressBytes);
      buffer.putShort((short) remoteServerPort);
      buffer.put(data, 0, packet.getLength());
      byte[] array = buffer.array();
      return new DatagramPacket(array, array.length, destinationAddress.getAddress(), destinationAddress.getPort());
    } else {
      throw new IllegalArgumentException("Only support java.net.InetSocketAddress");
    }
  }

  @Override
  public void decapsulate(DatagramPacket packet) throws IOException {
    ByteBuffer buffer = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());

    if (buffer.getShort() != 0) {
      // check reserved byte.
      throw new IOException("SOCKS version error");
    }
    if (buffer.get() != 0) {
      throw new IOException("SOCKS fragment is not supported");
    }
    InetAddress remoteServerAddress;
    int remoteServerPort;
    byte[] originalData;

    int addrType = buffer.get() & 0xff;
    switch (addrType) {

      case IPV4:
        try {
          byte[] ipv4 = new byte[4];
          buffer.get(ipv4);
          remoteServerAddress = InetAddress.getByAddress(ipv4);
        } catch (UnknownHostException e) {
          throw new IOException("Unknown host", e);
        }
        break;

      case IPV6:
        try {
          byte[] ipv6 = new byte[16];
          buffer.get(ipv6);
          remoteServerAddress = InetAddress.getByAddress(ipv6);
        } catch (UnknownHostException e) {
          throw new IOException("Unknown host", e);
        }
        break;

      case DOMAIN_NAME:
        final int DOMAIN_LENGTH = buffer.get() & 0xff;
        byte[] domainBytes = new byte[DOMAIN_LENGTH];
        buffer.get(domainBytes);
        String domainName = new String(domainBytes);
        try {
          remoteServerAddress = InetAddress.getByName(domainName);
        } catch (UnknownHostException e) {
          throw new IOException("Unknown host", e);
        }
        break;

      default:
        throw new IllegalStateException("Unexpected addrType: " + addrType);
    }

    remoteServerPort = buffer.getShort() & 0xffff;
    originalData = new byte[buffer.remaining()];
    buffer.get(originalData);

    packet.setAddress(remoteServerAddress);
    packet.setPort(remoteServerPort);
    packet.setData(originalData);
  }
}
