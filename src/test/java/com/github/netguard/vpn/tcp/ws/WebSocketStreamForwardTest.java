package com.github.netguard.vpn.tcp.ws;

import com.github.netguard.vpn.IPacketCapture;
import com.github.netguard.vpn.InspectorVpn;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HTTP/1.1 path, run through both forwards against a scripted server: only an upgrade answered with 101 becomes a
 * WebSocket. Everything else is relayed unchanged and, unless it started as an upgrade request, reported to the
 * packet capture like any other MITM connection.
 */
public class WebSocketStreamForwardTest extends TestCase {

    private static final InetSocketAddress CLIENT = new InetSocketAddress("127.0.0.1", 1);
    private static final InetSocketAddress SERVER = new InetSocketAddress("127.0.0.1", 2);
    private static final String HOST = "ws.example.com";

    private static final String UPGRADE_REQUEST = "GET /chat HTTP/1.1\r\n" +
            "Host: ws.example.com\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
            "Sec-WebSocket-Version: 13\r\n\r\n";
    private static final String SWITCHING_PROTOCOLS = "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    private static class RecordingFilter implements WebSocketFilter {
        final List<String> events = Collections.synchronizedList(new ArrayList<>());

        @Override
        public boolean filterHost(String hostName) {
            return true;
        }

        @Override
        public void onConnected(WebSocketSession session, WebSocketInjector injector) {
            events.add("connected ready=" + injector.isReady());
        }

        @Override
        public WebSocketFrame onFrame(WebSocketSession session, boolean fromServer, WebSocketFrame frame) {
            events.add("frame fromServer=" + fromServer + " " + frame.text());
            return frame;
        }

        @Override
        public void onClosed(WebSocketSession session) {
            events.add("closed");
        }
    }

    /** Stands in for both the VPN and its packet capture, recording what the forwards report. */
    private static class RecordingCapture implements InvocationHandler {
        final ByteArrayOutputStream tx = new ByteArrayOutputStream();
        final ByteArrayOutputStream rx = new ByteArrayOutputStream();
        private final Object capture = Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{IPacketCapture.class}, this);
        final InspectorVpn vpn = (InspectorVpn) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{InspectorVpn.class}, this);

        @Override
        public synchronized Object invoke(Object proxy, Method method, Object[] args) throws IOException {
            switch (method.getName()) {
                case "getPacketCapture":
                    return capture;
                case "onSSLProxyTx":
                    tx.write((byte[]) args[2]);
                    return null;
                case "onSSLProxyRx":
                    rx.write((byte[]) args[2]);
                    return null;
                case "toString":
                    return "RecordingCapture";
                default:
                    throw new UnsupportedOperationException(method.toString());
            }
        }
    }

    private static class Run {
        final RecordingFilter filter = new RecordingFilter();
        final RecordingCapture capture = new RecordingCapture();
        final WebSocketSession session = new WebSocketSession(CLIENT, SERVER, HOST);
        final ByteArrayOutputStream toServer = new ByteArrayOutputStream();
        final ByteArrayOutputStream toClient = new ByteArrayOutputStream();
    }

    /**
     * The client sends <code>fromClient</code> and closes. The server answers <code>fromServer</code> once it has
     * received a complete request head (or once the client has closed, if no head ever comes), then closes.
     */
    private static Run run(byte[] fromClient, byte[] fromServer) throws Exception {
        Run run = new Run();
        PipedInputStream serverIn = new PipedInputStream(1 << 16);
        PipedOutputStream proxyToServer = new PipedOutputStream(serverIn);
        PipedInputStream proxyFromServer = new PipedInputStream(1 << 16);
        PipedOutputStream serverOut = new PipedOutputStream(proxyFromServer);

        CountDownLatch finished = new CountDownLatch(2);
        WebSocketStreamForward inbound = new WebSocketStreamForward(new ByteArrayInputStream(fromClient), proxyToServer, true,
                CLIENT, SERVER, finished, new Socket(), run.capture.vpn, HOST, run.session, run.filter, null, null);
        WebSocketStreamForward outbound = new WebSocketStreamForward(proxyFromServer, run.toClient, false,
                CLIENT, SERVER, finished, new Socket(), run.capture.vpn, HOST, run.session, run.filter, null, null);
        outbound.setInjector(WebSocketStreamForward.newInjector(inbound, outbound, run.session));

        AtomicReference<IOException> serverError = new AtomicReference<>();
        Thread server = new Thread(() -> {
            try {
                boolean answered = false;
                int match = 0;
                int c;
                while ((c = serverIn.read()) >= 0) {
                    run.toServer.write(c);
                    if (!answered) {
                        boolean next = (c == '\r' && (match == 0 || match == 2)) || (c == '\n' && (match == 1 || match == 3));
                        match = next ? match + 1 : 0;
                        if (match == 4) {
                            serverOut.write(fromServer);
                            serverOut.close();
                            answered = true;
                        }
                    }
                }
                if (!answered) {
                    serverOut.write(fromServer);
                    serverOut.close();
                }
            } catch (IOException e) {
                serverError.set(e);
            }
        }, "scripted server");

        server.start();
        inbound.startThread(null);
        outbound.startThread(null);
        assertTrue("forwards did not finish", finished.await(10, TimeUnit.SECONDS));
        TimeUnit.SECONDS.timedJoin(server, 10);
        assertNull(serverError.get());
        return run;
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(a, 0, a.length);
        out.write(b, 0, b.length);
        return out.toByteArray();
    }

    private static byte[] textFrame(String text, boolean mask) {
        return WebSocketCodec.encode(WebSocketFrame.OPCODE_TEXT, true, text.getBytes(StandardCharsets.UTF_8), mask);
    }

    private static String text(ByteArrayOutputStream out) {
        return new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    private static String text(byte[] data) {
        return new String(data, StandardCharsets.ISO_8859_1);
    }

    public void testUpgradeAnsweredWith101() throws Exception {
        byte[] fromClient = concat(bytes(UPGRADE_REQUEST), textFrame("ping", true));
        byte[] fromServer = concat(bytes(SWITCHING_PROTOCOLS), textFrame("pong", false));

        Run run = run(fromClient, fromServer);

        List<String> events = new ArrayList<>(run.filter.events);
        assertEquals(events.toString(), 4, events.size());
        assertEquals("connected ready=true", events.get(0));
        assertTrue(events.toString(), events.contains("frame fromServer=false ping"));
        assertTrue(events.toString(), events.contains("frame fromServer=true pong"));
        assertEquals("closed", events.get(3));
        assertTrue(run.session.isEstablished());
        assertEquals(text(fromClient), text(run.toServer));
        assertEquals(text(fromServer), text(run.toClient));
        assertEquals("", text(run.capture.tx));
        assertEquals("", text(run.capture.rx));
    }

    public void testRejectedUpgrade() throws Exception {
        String response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";

        Run run = run(bytes(UPGRADE_REQUEST), bytes(response));

        assertEquals(new ArrayList<String>(), run.filter.events);
        assertFalse(run.session.isEstablished());
        assertEquals(UPGRADE_REQUEST, text(run.toServer));
        assertEquals(response, text(run.toClient));
        assertEquals("", text(run.capture.tx));
        assertEquals("", text(run.capture.rx));
    }

    public void testPlainRequest() throws Exception {
        String request = "POST /api HTTP/1.1\r\nHost: ws.example.com\r\nContent-Length: 5\r\n\r\nhello";
        String response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";

        Run run = run(bytes(request), bytes(response));

        assertEquals(new ArrayList<String>(), run.filter.events);
        assertFalse(run.session.isEstablished());
        assertEquals(request, text(run.toServer));
        assertEquals(response, text(run.toClient));
        assertEquals(request, text(run.capture.tx));
        assertEquals(response, text(run.capture.rx));
    }

    public void testGetWithoutUpgrade() throws Exception {
        String request = "GET /index.html HTTP/1.1\r\nHost: ws.example.com\r\n\r\n";
        String response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

        Run run = run(bytes(request), bytes(response));

        assertEquals(new ArrayList<String>(), run.filter.events);
        assertEquals(request, text(run.toServer));
        assertEquals(response, text(run.toClient));
        assertEquals(request, text(run.capture.tx));
        assertEquals(response, text(run.capture.rx));
    }

    public void testNotHttp() throws Exception {
        byte[] request = {0x10, 0x0c, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00};
        byte[] response = {0x20, 0x02, 0x00, 0x00};

        Run run = run(request, response);

        assertEquals(new ArrayList<String>(), run.filter.events);
        assertEquals(text(request), text(run.toServer));
        assertEquals(text(response), text(run.toClient));
        assertEquals(text(request), text(run.capture.tx));
        assertEquals(text(response), text(run.capture.rx));
    }
}
