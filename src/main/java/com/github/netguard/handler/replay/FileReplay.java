package com.github.netguard.handler.replay;

import com.alibaba.fastjson.JSON;
import com.github.netguard.VpnServer;
import org.apache.commons.io.FileUtils;
import org.krakenapps.pcap.Protocol;
import org.krakenapps.pcap.decoder.http.HttpDecoder;
import org.krakenapps.pcap.decoder.tcp.TcpSessionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class FileReplay extends Replay {

    private static final Logger log = LoggerFactory.getLogger(FileReplay.class);

    private final VpnServer server;
    private final File logFile;

    public FileReplay(VpnServer server, File logFile) {
        this.server = server;
        this.logFile = logFile;
        try {
            FileUtils.touch(logFile);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void doReplayInternal(HttpDecoder httpDecoder) throws IOException {
        List<String> lines = FileUtils.readLines(logFile, StandardCharsets.UTF_8);
        boolean hasLog = !lines.isEmpty();
        if (hasLog) {
            System.out.println("Start replay log file: " + logFile.getAbsolutePath());
        }
        for(String line : lines) {
            ReplayLog replayLog = JSON.parseObject(line, ReplayLog.class);
            replayLog.replay(httpDecoder);
        }
        if (hasLog) {
            System.out.println("End replay log file: " + logFile.getAbsolutePath());
        }
    }

    private void writeLog(ReplayLog replayLog) throws IOException {
        log.debug("writeLog: {}", replayLog);
        synchronized (server) {
            FileUtils.write(logFile, JSON.toJSONString(replayLog), StandardCharsets.UTF_8, true);
        }
    }

    @Override
    public void writeTcpConnect(TcpSessionKey key, Protocol protocol) throws IOException {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpConnect).setProtocol(protocol));
    }

    @Override
    public void writeTcpClose(TcpSessionKey key) throws IOException {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpClose));
    }

    @Override
    public void writeTcpSend(TcpSessionKey key, byte[] data) throws IOException {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpSend, data));
    }

    @Override
    public void writeTcpReceive(TcpSessionKey key, byte[] data) throws IOException {
        writeLog(ReplayLog.createLog(key, ReplayEvent.TcpReceive, data));
    }

    @Override
    public void writeLog(String log) throws IOException {
        if (log != null) {
            writeLog(new ReplayLog(ReplayEvent.Log, log.getBytes(StandardCharsets.UTF_8)));
        }
    }
}
