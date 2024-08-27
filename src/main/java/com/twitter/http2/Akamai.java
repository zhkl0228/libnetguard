package com.twitter.http2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

class Akamai {

    private static final Logger log = LoggerFactory.getLogger(Akamai.class);

    private HttpSettingsFrame httpSettingsFrame;

    void onHttpSettingsFrame(HttpSettingsFrame httpSettingsFrame) {
        if (this.httpSettingsFrame == null) {
            this.httpSettingsFrame = httpSettingsFrame;
        }
    }

    public String getText() {
        if (httpSettingsFrame == null || httpHeadersFrame == null) {
            log.debug("httpSettingsFrame({}) or httpHeadersFrame({}) is null", httpHeadersFrame != null, httpHeadersFrame != null);
            return null;
        }
        StringBuilder builder = new StringBuilder();
        {
            List<String> list = new ArrayList<>(5);
            for (Integer id : httpSettingsFrame.getIds()) {
                list.add(id + ":" + httpSettingsFrame.getValue(id));
            }
            builder.append(String.join(";", list)).append("|");
        }
        builder.append(windowSize == 0 ? "00" : String.valueOf(windowSize)).append("|");
        if (priorityFrames.isEmpty()) {
            builder.append("0");
        } else {
            builder.append(String.join(",", priorityFrames));
        }
        builder.append("|");
        {
            List<String> list = new ArrayList<>(4);
            for (Map.Entry<String, String> e : httpHeadersFrame.headers()) {
                switch (e.getKey()) {
                    case ":method":
                        list.add("m");
                        break;
                    case ":scheme":
                        list.add("s");
                        break;
                    case ":path":
                        list.add("p");
                        break;
                    case ":authority":
                        list.add("a");
                        break;
                }
            }
            builder.append(String.join(",", list));
        }
        return builder.toString();
    }

    private int windowSize;

    void onWindowUpdateFrame(int windowSize) {
        if (this.windowSize == 0) {
           this.windowSize = windowSize;
        }
    }

    private final List<String> priorityFrames = new ArrayList<>();

    void onPriorityFrame(int streamId, boolean exclusive, int dependency, int weight) {
        priorityFrames.add(new PriorityFrame(streamId, exclusive, dependency, weight).toString());
    }

    private HttpHeadersFrame httpHeadersFrame;

    void onHttpHeadersFrame(HttpHeadersFrame httpHeadersFrame) {
        if (this.httpHeadersFrame == null) {
            this.httpHeadersFrame = httpHeadersFrame;
        }
    }

    private static class PriorityFrame {
        final int streamId;
        final boolean exclusive;
        final int dependency;
        final int weight;
        PriorityFrame(int streamId, boolean exclusive, int dependency, int weight) {
            this.streamId = streamId;
            this.exclusive = exclusive;
            this.dependency = dependency;
            this.weight = weight;
        }
        @Override
        public String toString() {
            return streamId + ":" + (exclusive ? 0 : 1) + ":" + dependency + ":" + weight;
        }
    }

}
