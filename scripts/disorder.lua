-- Configuration Profile: Disorder2
-- Alternative fragmentation method

payload = { }
filter_tcp = "22"

-- Reorder packets to confuse DPI
dpi_desync = "disorder2"

-- Lighter fooling method
dpi_desync_fooling = "badseq"

-- No fake HTTP payload needed
-- dpi_desync_fake_http = ""

-- Standard MSS for better ping
tcp_mss = 1320
