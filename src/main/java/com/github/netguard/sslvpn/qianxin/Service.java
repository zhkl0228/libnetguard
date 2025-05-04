package com.github.netguard.sslvpn.qianxin;

import com.alibaba.fastjson.JSONObject;

public class Service {

    private final String name;
    private final String serverIp;
    private final String serverName;

    public Service(String name, String serverIp, String serverName) {
        this.name = name;
        this.serverIp = serverIp;
        this.serverName = serverName;
    }

    private int servicePort;

    public final Service setServicePort(int port, ServiceType serviceType) {
        this.servicePort = port;
        this.serviceType = serviceType;
        return this;
    }

    private boolean hide;

    public Service setHide() {
        this.hide = true;
        return this;
    }

    public enum AccessType {
        PROXY, // 应用级代理模式: VPN_PROXY_ACCESS
        NC, // VPN_PRD_DATA
        RAP,
        WEB,
        RDP
    }

    public enum ServiceType {
        none,
        http,
        https,
        ftp,
        telnet,
        ssh,
        ldap,
        mysql,
        imap,
        oracle,
        smtp,
        pop3,
        sqlserver,
        terminal,
        tftp,
        vnc,
        fileshare,
        exchange,
        fixedTCP,
        fixedUDP,
    }

    private AccessType accessType = AccessType.PROXY;

    public void setAccessType(AccessType accessType) {
        this.accessType = accessType;
    }

    private ServiceType serviceType = ServiceType.none;

    public final JSONObject toJSON(int id) {
        boolean isService = servicePort > 0;
        JSONObject service = new JSONObject(true);
        service.put("accesstype", accessType.ordinal());
        service.put("client_hide", hide ? 3 : 0); // 2, 3 means hide
        service.put("groupid", 0);
        service.put("id", id);
        service.put("index_page", "");
        service.put("name", name);
        service.put("path", isService ? "/" : "");
        service.put("remark", "");
        service.put("serverip", serverIp);
        service.put("servername", serverName);
        service.put("service_from", 0);
        service.put("servicetype", serviceType.ordinal());
        service.put("sort", id);
        service.put("throughput", 0);
        service.put("throughput_yn", 0);
        service.put("typeport", isService ? "T:" + servicePort : "any:NA");
        return service;
    }

}
