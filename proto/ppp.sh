#!/bin/sh

. netifd-proto.sh

ppp_init_config() {
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_int "keepalive"
}

ppp_setup() {
	echo "ppp_setup: $1"
}

ppp_teardown() {
	return
}

ppp_init() {
	no_device=1
	available=1
}

add_protocol ppp

pppoe_init_config() {
	ppp_init_config
}

pppoe_init() {
	return
}

pppoe_setup() {
	echo "pppoe_setup: $1"
}

pppoe_teardown() {
	return
}

add_protocol pppoe
