/*
 * Filename: Inspector.java
 * Create date: 2009-7-5
 */
package com.github.netguard;

import cn.hutool.core.util.HexUtil;
import cn.hutool.crypto.digest.DigestUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;


public class Inspector {
	
	public static void available(InputStream dis) throws IOException {
		if(dis == null) {
			System.out.println("available=null");
			return;
		}

		int size = dis.available();
		byte[] data = new byte[size];
		if (dis.read(data) != size) {
			throw new IOException("Read available failed.");
		}
		Inspector.inspect(data, "Available");
	}
	
	public static final int WPE = 16;
	
	public static void inspect(Date date, String label, byte[] data, int mode) {
		System.out.println(inspectInternal(date, label, data, mode));
	}

	private static String inspectInternal(Date date, String label, byte[] data, int mode) {
		StringBuilder buffer = new StringBuilder();
		buffer.append("\n>-----------------------------------------------------------------------------<\n");

		if (date == null) {
			date = new Date();
		}
		buffer.append(new SimpleDateFormat("[HH:mm:ss SSS]").format(date));

		buffer.append(label);
		if(data != null) {
			buffer.append(", md5=").append(DigestUtil.md5Hex(data));
			if (data.length < 1024) {
				buffer.append(", hex=").append(HexUtil.encodeHexStr(data));
			}
		}
		
		buffer.append("\nsize: ");
		if(data != null) {
			buffer.append(data.length);
		} else {
			buffer.append("null");
		}
		buffer.append('\n');
		
		if(data != null) {
			int i = 0;
			for(; i < data.length; i++) {
				if(i % mode == 0) {
					String hex = Integer.toHexString(i % 0x10000).toUpperCase();
					for(int k = 0, fill = 4 - hex.length(); k < fill; k++) {
						buffer.append('0');
					}
					buffer.append(hex).append(": ");
				}
				
				int di = data[i] & 0xFF;
				String hex = Integer.toString(di, 16).toUpperCase();
				if(hex.length() < 2) {
					buffer.append('0');
				}
				buffer.append(hex);
				buffer.append(' ');
				
				if((i + 1) % mode == 0) {
					buffer.append("   ");
					for(int k = i - 15; k < i+1; k++) {
						buffer.append(toChar(data[k]));
					}
					buffer.append('\n');
				}
			}

			appendSuffix(data, mode, buffer, i);
		}
		
		buffer.append("^-----------------------------------------------------------------------------^");
		
		return buffer.toString();
	}

	private static void appendSuffix(byte[] data, int mode, StringBuilder buffer, int i) {
		int redex = mode - i % mode;
		for(byte k = 0; k < redex && redex < mode; k++) {
			buffer.append("  ");
			buffer.append(' ');
		}
		int count = i % mode;
		int start = i - count;
		if(start < i) {
			buffer.append("   ");
		}
		for(int k = start; k < i; k++) {
			buffer.append(toChar(data[k]));
		}

		if(redex < mode) {
			buffer.append('\n');
		}
	}

	public static void inspect(String label, byte[] data, int mode) {
		inspect(null, label, data, mode);
	}

	/**
	 * 侦察发送的数据
	 */
	public static void inspect(byte[] data, String label) {
		inspect(label, data, WPE);
	}
	
	private static char toChar(byte in) {
		if(in == ' ')
			return ' ';
		
		if(in > 0x7E || in < 0x21)
			return '.';
		else
			return (char) in;
	}
	
	public static void where() {
		Thread.dumpStack();
	}
	
	public static void where(int testValue, int printValue) {
		if(testValue != printValue) {
			return;
		}

		where();
	}
	
	protected static void close(InputStream is) {
		if(is == null) {
			return;
		}
		
		try {
			is.close();
		} catch(Exception ignored) {}
	}
	protected static void close(OutputStream os) {
		if(os == null) {
			return;
		}
		
		try {
			os.close();
		} catch(Exception ignored) {}
	}
	
	public static String inspectString(String label, byte[] data, int mode) {
		return inspectString(null, label, data, mode);
	}
	
	public static String inspectString(Date date, String label, byte[] data, int mode) {
		return inspectInternal(date, label, data, mode);
	}

	/**
	 * 侦察发送的数据
	 */
	public static String inspectString(byte[] data, String label) {
		return inspectString(label, data, WPE);
	}

	public static String detectLanIP() throws SocketException {
		String lanIP = null;
		Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
		while(networkInterfaces.hasMoreElements()) {
			NetworkInterface networkInterface = networkInterfaces.nextElement();
			if (networkInterface.isLoopback() ||
					networkInterface.isVirtual() ||
					networkInterface.isPointToPoint()) {
				continue;
			}
			Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
			while (addresses.hasMoreElements()) {
				InetAddress address = addresses.nextElement();
				if(address.isLoopbackAddress()) {
					continue;
				}
				if (address instanceof Inet4Address) {
					lanIP = address.getHostAddress();
				}
			}
		}
		return lanIP;
	}

}
