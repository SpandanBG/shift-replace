dev:
	go run main.go

test-domain:
	curl -v -x socks5h://127.0.0.1 https://google.com

test-ipv4:
	curl -v -x socks5h://127.0.0.1 -k https://93.184.216.34

test-ipv6:
	curl -v -g -x socks5h://127.0.0.1 -k "https://[2606:2800:220:1:248:1893:25c8:1946]"
