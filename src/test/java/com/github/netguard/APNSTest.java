package com.github.netguard;

import com.eatthepath.pushy.apns.ApnsClient;
import com.eatthepath.pushy.apns.ApnsClientBuilder;
import com.eatthepath.pushy.apns.ApnsPushNotification;
import com.eatthepath.pushy.apns.DeliveryPriority;
import com.eatthepath.pushy.apns.PushNotificationResponse;
import com.eatthepath.pushy.apns.PushType;
import com.eatthepath.pushy.apns.util.ApnsPayloadBuilder;
import com.eatthepath.pushy.apns.util.SimpleApnsPayloadBuilder;
import com.eatthepath.pushy.apns.util.SimpleApnsPushNotification;

import java.io.InputStream;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class APNSTest {

    public static void main(String[] args) throws Exception {
        new APNSTest().testSendNotification();
    }

    public void testSendNotification() throws Exception {
        try (InputStream inputStream = getClass().getResourceAsStream("/aps/aps_development.p12")) {
            final ApnsClient client = new ApnsClientBuilder()
                    .setApnsServer(ApnsClientBuilder.DEVELOPMENT_APNS_HOST)
                    .setClientCredentials(inputStream, "")
                    .setConcurrentConnections(1)
                    .build();
            try {
                String apnsToken = "11df5144a2f4eb0a82389a13fc9b2a03009ddbf60f16c83b45cb19872cddcc14";
                ApnsPayloadBuilder builder = new SimpleApnsPayloadBuilder();
                builder.setContentAvailable(true);
                ApnsPushNotification notification = new SimpleApnsPushNotification(apnsToken, "com.github.zhkl0228.inspector.vpn", builder.build(),
                        null, DeliveryPriority.CONSERVE_POWER, PushType.BACKGROUND, null, null);
                System.out.println(notification);
                Future<PushNotificationResponse<ApnsPushNotification>> future = client.sendNotification(notification);
                PushNotificationResponse<ApnsPushNotification> response = future.get(30, TimeUnit.SECONDS);
                System.out.println(response);
                if (!response.isAccepted()) {
                    throw new IllegalStateException(response.getRejectionReason().orElse(response.toString()));
                }
            } finally {
                client.close();
            }
        }
    }

}
