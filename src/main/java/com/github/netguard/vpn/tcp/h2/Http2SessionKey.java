package com.github.netguard.vpn.tcp.h2;

import java.util.Objects;

public class Http2SessionKey {

    private final Http2Session session;
    private final int streamId;
    private final boolean h3;

    public Http2SessionKey(Http2Session session, int streamId, boolean h3) {
        this.session = session;
        this.streamId = streamId;
        this.h3 = h3;
    }

    public Http2Session getSession() {
        return session;
    }

    public boolean isH3() {
        return h3;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Http2SessionKey that = (Http2SessionKey) o;
        return streamId == that.streamId && Objects.equals(session, that.session);
    }

    @Override
    public int hashCode() {
        return Objects.hash(session, streamId);
    }

    @Override
    public String toString() {
        return session.toString();
    }

}
