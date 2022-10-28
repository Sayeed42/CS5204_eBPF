all: tc_icmp xdp_icmp

tc_icmp:
	make -C tc_icmp

xdp_icmp:
	make -C xdp_icmp

clean:
	make -C tc_icmp clean
	make -C xdp_icmp clean

.PHONY: tc_icmp xdp_icmp