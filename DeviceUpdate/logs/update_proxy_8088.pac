function FindProxyForURL(url, host) {
  if (url.slice(0,7) == "http://") {
    if (isInNet(host, "192.168.200.0", "255.255.255.0")) return "PROXY 127.0.0.1:8088";
  }
  return "DIRECT";
}