package com.github.netguard.handler.http;

/**
 * @author zhkl0228
 *
 */
public interface HttpResponse extends HttpEntity {

    /**
     * 返回码
     * @return responseCode
     */
    int getResponseCode();

    /**
     * 返回码消息
     * @return responseCodeMsg
     */
    String getResponseCodeMsg();

    /**
     * 请求版本
     * @return requestVersion
     */
    String getRequestVersion();

    /**
     * 内容编码
     * @return contentEncoding
     */
    String getContentEncoding();

    /**
     * 传输编码
     * @return transferEncoding
     */
    String getTransferEncoding();

    /**
     * 内容类型
     * @return contentType
     */
    String getContentType();

    /**
     * 返回内容
     * @return responseData
     */
    byte[] getResponseData();

}
