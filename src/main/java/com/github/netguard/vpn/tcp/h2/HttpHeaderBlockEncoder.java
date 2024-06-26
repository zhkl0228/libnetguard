/*
 * Copyright 2015 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.netguard.vpn.tcp.h2;

import com.twitter.hpack.NetGuardEncoder;
import com.twitter.http2.HttpHeaderBlockFrame;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufOutputStream;
import io.netty.buffer.Unpooled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

public class HttpHeaderBlockEncoder {

    private static final Logger log = LoggerFactory.getLogger(HttpHeaderBlockEncoder.class);

    private static final byte[] COOKIE = {'c', 'o', 'o', 'k', 'i', 'e'};
    private static final byte[] EMPTY = {};

    private int encoderMaxHeaderTableSize;
    private int decoderMaxHeaderTableSize;
    private int maxHeaderTableSize;
    private final NetGuardEncoder encoder;

    /**
     * Create a new instance.
     */
    public HttpHeaderBlockEncoder(int maxHeaderTableSize) {
        encoderMaxHeaderTableSize = maxHeaderTableSize;
        decoderMaxHeaderTableSize = maxHeaderTableSize;
        this.maxHeaderTableSize = maxHeaderTableSize;
        encoder = new NetGuardEncoder(maxHeaderTableSize);
    }

    /**
     * Set the maximum header table size allowed by the encoder.
     *
     * @param encoderMaxHeaderTableSize the maximum header table size allowed by the encoder
     */
    public void setEncoderMaxHeaderTableSize(int encoderMaxHeaderTableSize) {
        this.encoderMaxHeaderTableSize = encoderMaxHeaderTableSize;
        if (encoderMaxHeaderTableSize < maxHeaderTableSize) {
            maxHeaderTableSize = encoderMaxHeaderTableSize;
        }
    }

    /**
     * Set the maximum header table size allowed by the peer's encoder.
     * This is the value of SETTINGS_HEADER_TABLE_SIZE received from the peer.
     *
     * @param decoderMaxHeaderTableSize the maximum header table size allowed by the decoder
     */
    public void setDecoderMaxHeaderTableSize(int decoderMaxHeaderTableSize) {
        this.decoderMaxHeaderTableSize = decoderMaxHeaderTableSize;
        if (decoderMaxHeaderTableSize < maxHeaderTableSize) {
            maxHeaderTableSize = decoderMaxHeaderTableSize;
        }
    }

    /**
     * Encode the header block frame.
     */
    public synchronized ByteBuf encode(HttpHeaderBlockFrame frame) throws IOException {
        ByteBuf buf = Unpooled.buffer();
        ByteBufOutputStream out = new ByteBufOutputStream(buf);

        // The current allowable max header table size is the
        // minimum of the encoder and decoder allowable sizes
        int allowableHeaderTableSize = Math.min(encoderMaxHeaderTableSize, decoderMaxHeaderTableSize);

        // maxHeaderTableSize will hold the smallest size seen the
        // last call to encode. This might be smaller than the
        // current allowable max header table size
        if (maxHeaderTableSize < allowableHeaderTableSize) {
            encoder.setMaxHeaderTableSize(out, maxHeaderTableSize);
        }

        // Check if the current allowable size is equal to the encoder's
        // capacity and set the new size if necessary
        if (allowableHeaderTableSize != encoder.getMaxHeaderTableSize()) {
            encoder.setMaxHeaderTableSize(out, allowableHeaderTableSize);
        }

        // Store the current allowable size for the next call
        maxHeaderTableSize = allowableHeaderTableSize;

        // Now we can encode headers
        for (String name : frame.headers().names()) {
            if ("cookie".equalsIgnoreCase(name)) {
                // Sec. 8.1.3.4. Cookie Header Field
                for (String value : frame.headers().getAll(name)) {
                    for (String crumb : value.split(";")) {
                        byte[] valueBytes = crumb.trim().getBytes(StandardCharsets.UTF_8);
                        if (log.isDebugEnabled()) {
                            log.debug("encodeCookie value={}", crumb.trim());
                        }
                        encoder.encodeHeader(out, COOKIE, valueBytes, true);
                    }
                }
            } else {
                byte[] nameBytes = name.toLowerCase(Locale.ENGLISH).getBytes(StandardCharsets.UTF_8);
                // Sec. 8.1.3.3. Header Field Ordering
                List<String> values = frame.headers().getAll(name);
                if (values.size() == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("encodeEmptyHeader name={}", name.toLowerCase(Locale.ENGLISH));
                    }
                    encoder.encodeHeader(out, nameBytes, EMPTY, false);
                } else {
                    for (String value : values) {
                        byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
                        if (log.isDebugEnabled()) {
                            log.debug("encodeHeader name={}, value={}", name.toLowerCase(Locale.ENGLISH), value);
                        }
                        encoder.encodeHeader(out, nameBytes, valueBytes, false);
                    }
                }
            }
        }

        return buf;
    }
}
