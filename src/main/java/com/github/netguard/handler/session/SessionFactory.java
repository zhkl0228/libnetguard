package com.github.netguard.handler.session;

import org.krakenapps.pcap.decoder.tcp.TcpSession;

/**
 * @author zhkl0228
 *
 */
public interface SessionFactory {
	
	Session createSession(TcpSession tcp);

}
