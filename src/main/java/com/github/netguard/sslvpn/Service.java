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

    final Service setServicePort(int port) {
        servicePort = port;
        return this;
    }

    enum AccessType {
        PROXY, // 应用级代理模式
        NC, // netcat
        RAP,
        WEB,
        RDP
    }

    final JSONObject toJSON(int id) {
        boolean isService = servicePort > 0;
        JSONObject service = new JSONObject(true);
        service.put("accesstype", isService ? AccessType.PROXY.ordinal() : AccessType.NC.ordinal());
        service.put("client_hide", isService ? 0 : 3); // 2, 3 means hide
        service.put("groupid", 0);
        service.put("id", id);
        service.put("index_page", "");
        service.put("name", name);
        service.put("path", isService ? "/" : "");
        service.put("remark", "");
        service.put("serverip", serverIp);
        service.put("servername", serverName);
        service.put("service_from", 0);
        service.put("servicetype", isService ? 1 : 23);
        service.put("sort", id);
        service.put("throughput", 0);
        service.put("throughput_yn", 0);
        service.put("typeport", isService ? "T:" + servicePort : "any:NA");
        return service;
    }

}
