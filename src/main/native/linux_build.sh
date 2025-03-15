JAVA_INC="$JAVA_HOME"/include
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

cc -m64 -o libnetguard.so -shared -fPIC -O2 -Wno-discarded-qualifiers -lrt \
  dhcp.c dns.c icmp.c ip.c netguard.c pcap.c session.c tcp.c udp.c util.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" && \
  mv libnetguard.so ../resources/natives/linux_64/
