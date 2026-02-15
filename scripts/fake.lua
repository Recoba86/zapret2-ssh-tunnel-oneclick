-- Configuration Profile: Fake HTTP
-- Aggressive method, higher ping, uses fake payloads

payload = { }
filter_tcp = "22"

-- Send a fake packet resembling a Google search
dpi_desync = "fake"
dpi_desync_fooling = "md5sig,badseq"

-- Crafted HTTP header for DPI deception
dpi_desync_fake_http = "GET /search?q=open+source+ssh+tunnel HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"

-- Reduced MSS to force fragmentation
tcp_mss = 1300
