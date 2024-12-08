package com.github.netguard.handler.replay;

import cn.hutool.core.io.FileUtil;
import com.alibaba.fastjson.JSON;
import com.github.netguard.VpnServer;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

public class FileReplay extends Replay {

    private static final Logger log = LoggerFactory.getLogger(FileReplay.class);

    private final VpnServer server;
    private final File logFile;

    public FileReplay(VpnServer server, File logFile) {
        this.server = server;
        FileUtil.touch(logFile);
        this.logFile = logFile;
    }

    @Override
    public void doReplay(HttpDecoder httpDecoder) {
        List<String> lines = FileUtil.readLines(logFile, StandardCharsets.UTF_8);
        if (!lines.isEmpty()) {
            System.out.println("Start replay log file: " + logFile.getAbsolutePath());
        }
        for(String line : lines) {
            ReplayLog replayLog = JSON.parseObject(line, ReplayLog.class);
            replayLog.replay(httpDecoder);
        }
    }

    private void writeLog(ReplayLog replayLog) {
        log.debug("writeLog: {}", replayLog);
        synchronized (server) {
            FileUtil.appendUtf8Lines(Collections.singletonList(JSON.toJSONString(replayLog)), logFile);
        }
    }

    @Override
    public void writeTcpConnect(TcpSessionKey key, Protocol protocol) {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpConnect).setProtocol(protocol));
    }

    @Override
    public void writeTcpClose(TcpSessionKey key) {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpClose));
    }

    @Override
    public void writeTcpSend(TcpSessionKey key, byte[] data) {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpSend, data));
    }

    @Override
    public void writeTcpReceive(TcpSessionKey key, byte[] data) {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpReceive, data));
    }

}
