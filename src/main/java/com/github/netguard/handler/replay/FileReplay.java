package com.github.netguard.handler.replay;

import cn.hutool.core.io.FileUtil;
import com.alibaba.fastjson.JSON;
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

    private static final Object lock = new Object();

    private final File logFile;

    public FileReplay(File logFile) {
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
            ReplayLog log = JSON.parseObject(line, ReplayLog.class);
            log.replay(httpDecoder);
        }
    }

    private void writeLog(ReplayLog log) {
        FileReplay.log.debug("writeLog: {}", log);
        synchronized (lock) {
            FileUtil.appendUtf8Lines(Collections.singletonList(JSON.toJSONString(log)), logFile);
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
