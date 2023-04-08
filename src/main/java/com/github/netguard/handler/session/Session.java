package com.github.netguard.handler.session;

import org.krakenapps.pcap.util.Buffer;

import java.io.IOException;

/**
 * @author zhkl0228
 *
 */
public interface Session {
	
	/**
	 * 处理发送
	 * @return true表示继续处理
	 * @throws DecodeFailedException 第一次解析抛出异常以后，则会进入fallbackTcpProcessor
	 */
	boolean processTx(Buffer buffer) throws IOException, DecodeFailedException;
	
	/**
	 * 处理接收
	 * @return false表示停止处理
	 */
	boolean processRx(Buffer buffer) throws IOException, DecodeFailedException;
	
	/**
	 * on tcp finish
	 */
	void onFinish();

}
