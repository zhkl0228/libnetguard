package com.github.netguard.handler.session;

import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSession;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author zhkl0228
 *
 */
public abstract class SessionCreator implements TcpProcessor, SessionFactory {
	
	private static final Logger log = LoggerFactory.getLogger(SessionCreator.class);
	
	private class InternalSession {
		final TcpSession tcpSession;
		final Session session;
		final Buffer txBuffer, rxBuffer;
		InternalSession(TcpSession tcpSession, Session session) {
			super();
			this.tcpSession = tcpSession;
			this.session = session;
			txBuffer = new ChainBuffer();
			rxBuffer = new ChainBuffer();
		}
		boolean isFirstTx = true;
		void processTx(Buffer data) throws IOException {
			txBuffer.addLast(data).compact();

			txBuffer.mark();
			try {
				while (txBuffer.readableBytes() > 0) {
					if (!session.processTx(txBuffer)) {
						break;
					}
				}
			} catch (DecodeFailedException e) {
				if (isFirstTx && SessionCreator.this.fallbackTcpProcessor != null) {
					this.fallbackTcpProcessor = SessionCreator.this.fallbackTcpProcessor;
                    log.debug("decode failed, fallback to: {}", fallbackTcpProcessor);
					txBuffer.reset();
					this.fallbackTcpProcessor.onEstablish(tcpSession);
					this.fallbackTcpProcessor.handleTx(tcpSession.getKey(), txBuffer);
				} else {
					log.warn("decode failed", e);
				}
			} finally {
				isFirstTx = false;
			}
		}
		void processRx(Buffer data) throws IOException {
			rxBuffer.addLast(data).compact();

			try {
				while (rxBuffer.readableBytes() > 0) {
					if (!session.processRx(rxBuffer)) {
						break;
					}
				}
			} catch (DecodeFailedException e) {
				log.warn("decode failed", e);
			}
		}
		private TcpProcessor fallbackTcpProcessor;
	}
	
	private final Map<TcpSessionKey, InternalSession> sessionMap = new HashMap<>();

	public SessionCreator() {
		super();
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.tcp.TcpProcessor#onReset(org.krakenapps.pcap.decoder.tcp.TcpSessionKey)
	 */
	@Override
	public final void onReset(TcpSessionKey key) {
		InternalSession s = sessionMap.remove(key);
		if(s != null) {
			if (s.fallbackTcpProcessor != null) {
				s.fallbackTcpProcessor.onReset(key);
			} else {
				s.session.onFinish();
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.tcp.TcpProcessor#onEstablish(org.krakenapps.pcap.decoder.tcp.TcpSession)
	 */
	@Override
	public final boolean onEstablish(TcpSession session) {
		Session s = this.createSession(session);
		if(s != null) {
			sessionMap.put(session.getKey(), new InternalSession(session, s));
			return true;
		} else {
			return false;
		}
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.tcp.TcpProcessor#onFinish(org.krakenapps.pcap.decoder.tcp.TcpSessionKey)
	 */
	@Override
	public final void onFinish(TcpSessionKey key) {
		InternalSession s = sessionMap.remove(key);
		if(s != null) {
			if (s.fallbackTcpProcessor != null) {
				s.fallbackTcpProcessor.onFinish(key);
			} else {
				s.session.onFinish();
			}
		}
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.tcp.TcpProcessor#handleTx(org.krakenapps.pcap.decoder.tcp.TcpSessionKey, org.krakenapps.pcap.util.Buffer)
	 */
	@Override
	public final void handleTx(TcpSessionKey session, Buffer data) {
		InternalSession s = this.sessionMap.get(session);
		if(s == null) {
			return;
		}
		
		try {
			if (s.fallbackTcpProcessor != null) {
				s.fallbackTcpProcessor.handleTx(session, data);
			} else {
				s.processTx(data);
			}
		} catch (IOException e) {
			log.debug(e.getMessage(), e);
		}
	}

	/* (non-Javadoc)
	 * @see org.krakenapps.pcap.decoder.tcp.TcpProcessor#handleRx(org.krakenapps.pcap.decoder.tcp.TcpSessionKey, org.krakenapps.pcap.util.Buffer)
	 */
	@Override
	public final void handleRx(TcpSessionKey session, Buffer data) {
		InternalSession s = this.sessionMap.get(session);
		if(s == null) {
			return;
		}
		
		try {
			if (s.fallbackTcpProcessor != null) {
				s.fallbackTcpProcessor.handleRx(session, data);
			} else {
				s.processRx(data);
			}
		} catch (IOException e) {
			log.debug(e.getMessage(), e);
		}
	}

	private TcpProcessor fallbackTcpProcessor;

	@SuppressWarnings("unused")
	public void setFallbackTcpProcessor(TcpProcessor fallbackTcpProcessor) {
		this.fallbackTcpProcessor = fallbackTcpProcessor;
	}

}
