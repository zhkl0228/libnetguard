package com.legendsec.vpnclient;

import cn.hutool.core.util.HexUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.github.netguard.Inspector;
import com.github.netguard.sslvpn.qianxin.QianxinVpn;
import org.krakenapps.pcap.decoder.tcp.DefaultTcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpProcessor;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.krakenapps.pcap.util.Buffer;
import org.krakenapps.pcap.util.ChainBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
class SacMsgProcessor extends DefaultTcpProcessor implements TcpProcessor {

    private static final Logger logger = LoggerFactory.getLogger(SacMsgProcessor.class);

    private final Map<TcpSessionKey, Buffer> txBuffer = new HashMap<>();
    private final Map<TcpSessionKey, Buffer> rxBuffer = new HashMap<>();

    @Override
    public void handleTx(TcpSessionKey session, Buffer data) {
        Buffer buffer = txBuffer.get(session);
        final Buffer newBuffer;
        newBuffer = new ChainBuffer();
        if (buffer != null) {
            newBuffer.addLast(buffer);
        }
        newBuffer.addLast(data);
        data = newBuffer;
        data.mark();
        int tag = data.getInt();
        switch (tag) {
            case QianxinVpn.VPN_GET_PORTAL:
            case QianxinVpn.VPN_LOGIN:
            case QianxinVpn.VPN_GET_USERDATA:
            case QianxinVpn.VPN_HEARTBEAT:
            case QianxinVpn.VPN_LOGOUT:
            case QianxinVpn.VPN_SMS_SEND:
            case QianxinVpn.VPN_SUB_AUTH:
            case QianxinVpn.VPN_QUERY_APP_LIST:
            {
                boolean haveData = handleMsgReq(tag, data);
                if(haveData) {
                    data.reset();
                    txBuffer.put(session, data);
                }
                break;
            }
            default:
                logger.debug("Received unknown req tag: 0x{}", Integer.toHexString(tag));
                break;
        }
    }

    @Override
    public void handleRx(TcpSessionKey session, Buffer data) {
        Buffer buffer = rxBuffer.get(session);
        final Buffer newBuffer = new ChainBuffer();
        if (buffer != null) {
            newBuffer.addLast(buffer);
        }
        newBuffer.addLast(data);
        data = newBuffer;
        data.mark();
        int tag = data.getInt();
        switch (tag & Integer.MAX_VALUE) {
            case QianxinVpn.VPN_GET_PORTAL:
            case QianxinVpn.VPN_LOGIN:
            case QianxinVpn.VPN_GET_USERDATA:
            case QianxinVpn.VPN_HEARTBEAT:
            case QianxinVpn.VPN_LOGOUT:
            case QianxinVpn.VPN_SMS_SEND:
            case QianxinVpn.VPN_SUB_AUTH:
            case QianxinVpn.VPN_QUERY_APP_LIST:
            {
                boolean haveData = handleMsgResp(tag, data, session);
                if(haveData) {
                    data.reset();
                    rxBuffer.put(session, data);
                }
                break;
            }
            default:
                logger.debug("Received unknown resp tag: 0x{}, key={}, bufferSize={}", Integer.toHexString(tag), session, buffer == null ? 0 : buffer.readableBytes());
                break;
        }
    }

    private boolean handleMsgResp(int tag, Buffer data, TcpSessionKey key) {
        int length = data.getInt();
        int readableBytes = data.readableBytes();
        if (readableBytes >= length) {
            int error = data.getInt();
            if (error == 0) {
                byte[] msg = new byte[length - 4];
                data.gets(msg);
                Inspector.inspect(msg, String.format("handleMsgResp tag=0x%s, readableBytes=%d, length=%d", Integer.toHexString(tag), readableBytes, length));
                ByteBuffer buffer = ByteBuffer.wrap(msg);
                if (buffer.remaining() >= 4 && buffer.getInt() > 0) {
                    byte[] json = new byte[buffer.remaining()];
                    buffer.get(json);
                    JSONObject obj = JSON.parseObject(new String(json, StandardCharsets.UTF_8).trim());
                    logger.info("handleMsgResp: tag=0x{}, {}", Integer.toHexString(tag), obj == null ? "json=" + HexUtil.encodeHexStr(json) : obj.toString(SerializerFeature.PrettyFormat));
                } else {
                    logger.info("handleMsgResp: tag=0x{}", Integer.toHexString(tag));
                }
            } else {
                String errorText = null;
                switch (error) {
                    case 0x2000404:
                        errorText = "无效用户，请重新登录";
                        break;
                    case 0x2000405:
                        errorText = "帐号或者密码错误";
                        break;
                    case 0x2000410:
                        errorText = "密码错误";
                        break;
                    case 0x2000419:
                        errorText = "密码强度不符合要求";
                        break;
                    case 0x200041b:
                        errorText = "验证旧密码失败";
                        break;
                    case 0x200043c:
                        errorText = "验证码发送失败";
                        break;
                    case 0x200043d:
                        errorText = "验证失败，请重试";
                        break;
                    case 0x2000658:
                        errorText = "账号不存在";
                        break;
                }
                if (errorText == null) {
                    logger.warn("Received error tag: 0x{}, error=0x{}", Integer.toHexString(tag), Integer.toHexString(error));
                } else {
                    logger.info("Received error tag: 0x{}, error=0x{}, text={}", Integer.toHexString(tag), Integer.toHexString(error), errorText);
                }
            }
            return false;
        } else {
            logger.info("Received wrong response tag=0x{}, length: {}, readableBytes={}, key={}", Integer.toHexString(tag), length, data.readableBytes(), key);
            return true;
        }
    }

    private boolean handleMsgReq(int tag, Buffer data) {
        int length = data.getInt();
        if (data.readableBytes() >= length) {
            byte[] msg = new byte[length];
            data.gets(msg);
            ByteBuffer buffer = ByteBuffer.wrap(msg);
            length = buffer.getInt();
            if (length <= buffer.remaining()) {
                byte[] json = new byte[length];
                buffer.get(json);
                JSONObject obj = JSON.parseObject(new String(json, StandardCharsets.UTF_8).trim());
                logger.info("handleMsgReq: tag=0x{}, {}", Integer.toHexString(tag), obj.toString(SerializerFeature.PrettyFormat));
            } else {
                logger.warn("Received wrong buffer length: {}, remaining={}", length, buffer.remaining());
            }
            return false;
        } else {
            logger.info("Received wrong request length: {}, readableBytes={}", length, data.readableBytes());
            return true;
        }
    }

    @Override
    public void onFinish(TcpSessionKey key) {
        super.onFinish(key);

        txBuffer.remove(key);
        rxBuffer.remove(key);
    }

}
