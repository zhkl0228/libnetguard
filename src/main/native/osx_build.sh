# https://github.com/jiixyj/epoll-shim

JAVA_INC="$(realpath "$JAVA_HOME"/include)"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

"$(/usr/libexec/java_home -v 1.8)"/bin/javah -cp ../../../target/classes eu.faircode.netguard.ServiceSinkhole && \
  xcrun -sdk macosx clang -m64 -o libnetguard.dylib -shared -O2 -Wno-incompatible-pointer-types-discards-qualifiers \
  dhcp.c dns.c icmp.c ip.c netguard.c pcap.c session.c tcp.c udp.c util.c \
  -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" -I include epoll-shim/libepoll-shim.a && \
  mv libnetguard.dylib ../resources/natives/osx_arm64/
