all:
	gcc dns_injector.c -o dnsinject -lresolv -lpcap -lnet
	gcc dns_detector.c -o dnsdetect -lresolv -lpcap -lnet
clean:
	rm dnsinject
	rm dnsdetect
