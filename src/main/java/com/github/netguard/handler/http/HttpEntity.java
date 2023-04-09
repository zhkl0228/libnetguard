package com.github.netguard.handler.http;

import java.util.Set;

/**
 * @author zhkl0228
 *
 */
public interface HttpEntity {

    /**
     * @return HTTP头
     */
    String getHeaderString();

    String getHeader(String name);

    Set<String> getHeaderKeys();

}
