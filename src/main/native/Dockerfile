FROM centos:7

RUN sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo && \
    sed -i 's|^#[ ]*baseurl=http://mirror.centos.org|baseurl=https://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo && \
    rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    yum install -y gcc make java-1.8.0-openjdk-devel && \
    yum clean all

ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk

WORKDIR /build/jni
COPY *.c *.h ./

RUN JAVA_INC="$JAVA_HOME/include" && \
    JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")" && \
    cc -o libnetguard.so -shared -fPIC -O2 -Wno-discarded-qualifiers -lrt \
      dhcp.c dns.c icmp.c ip.c netguard.c pcap.c session.c tcp.c udp.c util.c \
      -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC"

CMD ["cp", "/build/jni/libnetguard.so", "/output/libnetguard.so"]
