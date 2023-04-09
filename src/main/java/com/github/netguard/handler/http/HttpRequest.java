package com.github.netguard.handler.http;

/**
 * @author zhkl0228
 *
 */
public interface HttpRequest extends HttpEntity {

    /**
     * @return http or https
     */
    String getScheme();

    /**
     * @return 请求Host
     */
    String getHost();

    /**
     * @return 请求端口
     */
    int getPort();

    /**
     * @return 请求uri
     */
    String getRequestUri();

    /**
     * @return 请求Method
     */
    String getRequestMethod();

    /**
     * 内容类型
     * @return contentType
     */
    String getContentType();

    /**
     * 如果有POST数据，则返回数据，否则返回0大小的数据
     * @return post data
     */
    byte[] getPostData();

    String getRequestLine();

}
