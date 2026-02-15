-- Configuration Profile: Split2
-- Balanced method, lower ping, packet fragmentation

payload = { }
filter_tcp = "22"

-- Split the original packet to bypass DPI reading
dpi_desync = "split2"

-- Lighter fooling method, requires less CPU
dpi_desync_fooling = "badseq"

-- No fake HTTP payload needed for split method
-- dpi_desync_fake_http = ""

-- Standard MSS for better ping
tcp_mss = 1320
