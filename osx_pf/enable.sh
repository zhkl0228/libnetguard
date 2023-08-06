# https://docs.mitmproxy.org/stable/howto-transparent/#macos
sudo sysctl -w net.inet.ip.forwarding=1
sudo pfctl -F all -ef pf.conf
