package com.github.netguard.sslvpn;

import com.alibaba.fastjson.JSONObject;

class Service {

    private final String name;
    private final String serverIp;
    private final String serverName;

    Service(String name, String serverIp, String serverName) {
        this.name = name;
        this.serverIp = serverIp;
        this.serverName = serverName;
    }

    private int servicePort;

    public final Service setServicePort(int port) {
        return setServicePort(port, AccessType.PROXY);
    }

    public final Service setServicePort(int port, AccessType accessType) {
        this.servicePort = port;
        this.accessType = accessType;
        return this;
    }

    private boolean hide;

    public Service setHide() {
        this.hide = true;
        return this;
    }

    enum AccessType {
        PROXY, // 应用级代理模式: VPN_PROXY_ACCESS
        NC, // VPN_PRD_DATA
    }

    private AccessType accessType = AccessType.PROXY;

    final JSONObject toJSON(int id) {
        boolean isService = servicePort > 0;
        JSONObject service = new JSONObject(true);
        service.put("accesstype", accessType.ordinal());
        service.put("client_hide", hide ? 2 : 1); // 2, 3 means hide
        service.put("groupid", 0);
        service.put("id", id);
        service.put("index_page", "");
        service.put("name", name);
        service.put("path", isService ? "/" : "");
        service.put("remark", "");
        service.put("serverip", serverIp);
        service.put("servername", serverName);
        service.put("service_from", 0);
        service.put("servicetype", isService ? 1 : 23); // 1, 5, 23
        service.put("sort", id);
        service.put("throughput", 0);
        service.put("throughput_yn", 0);
        service.put("typeport", isService ? "T:" + servicePort : "any:NA");
        return service;
    }

}
