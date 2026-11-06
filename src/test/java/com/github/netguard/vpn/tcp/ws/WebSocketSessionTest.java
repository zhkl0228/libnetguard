package com.github.netguard.vpn.tcp.ws;

import junit.framework.TestCase;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * {@link WebSocketSession} calls {@link WebSocketFilter#onConnected} and {@link WebSocketFilter#onClosed} once each,
 * in that order, and never onClosed for a session that did not connect.
 */
public class WebSocketSessionTest extends TestCase {

    private static class RecordingFilter implements WebSocketFilter {
        final List<String> events = new ArrayList<>();

        @Override
        public boolean filterHost(String hostName) {
            return true;
        }

        @Override
        public void onConnected(WebSocketSession session, WebSocketInjector injector) {
            events.add("connected");
        }

        @Override
        public WebSocketFrame onFrame(WebSocketSession session, boolean fromServer, WebSocketFrame frame) {
            return frame;
        }

        @Override
        public void onClosed(WebSocketSession session) {
            events.add("closed");
        }
    }

    private final WebSocketSession session = new WebSocketSession(
            new InetSocketAddress("127.0.0.1", 1), new InetSocketAddress("127.0.0.1", 2), "ws.example.com");
    private final RecordingFilter filter = new RecordingFilter();

    public void testClosesAfterBothDirectionsEnd() {
        session.connect(filter, null);
        assertTrue(session.isEstablished());
        session.endStream(filter);
        assertEquals(Arrays.asList("connected"), filter.events);
        session.endStream(filter);
        assertEquals(Arrays.asList("connected", "closed"), filter.events);
    }

    public void testClosedOnce() {
        session.connect(filter, null);
        session.close(filter);
        session.close(filter);
        session.endStream(filter);
        session.endStream(filter);
        assertEquals(Arrays.asList("connected", "closed"), filter.events);
    }

    public void testNoCallbacksWithoutConnect() {
        session.endStream(filter);
        session.endStream(filter);
        session.close(filter);
        assertEquals(new ArrayList<String>(), filter.events);
        assertFalse(session.isEstablished());
    }

    public void testCloseBeforeConnectFollowsOnConnected() {
        session.close(filter);
        session.connect(filter, null);
        assertEquals(Arrays.asList("connected", "closed"), filter.events);
    }

    public void testCloseWhileOnConnectedRuns() {
        RecordingFilter closingFilter = new RecordingFilter() {
            @Override
            public void onConnected(WebSocketSession session, WebSocketInjector injector) {
                super.onConnected(session, injector);
                session.close(this);   // what the other direction does when it ends at this moment
                events.add("onConnected returns");
            }
        };
        session.connect(closingFilter, null);
        session.close(closingFilter);
        assertEquals(Arrays.asList("connected", "onConnected returns", "closed"), closingFilter.events);
    }
}
