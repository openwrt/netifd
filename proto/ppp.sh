#!/bin/sh

. netifd-proto.sh

ppp_init_config() {
	proto_config_add_string "username"
	proto_config_add_string "password"
	proto_config_add_int "keepalive"
}

ppp_init() {
	return
}

add_protocol ppp

pppoe_init_config() {
	ppp_init_config
}

pppoe_init() {
	return
}

add_protocol pppoe
