. /usr/share/libubox/jshn.sh

proto_config_add_generic() {
	json_add_array ""
	json_add_string "" "$1"
	json_add_int "" "$2"
	json_close_array
}

proto_config_add_int() {
	proto_config_add_generic "$1" 5
}

proto_config_add_string() {
	proto_config_add_generic "$1" 3
}

proto_config_add_boolean() {
	proto_config_add_generic "$1" 7
}

add_default_handler() {
	case "$(type $1 2>/dev/null)" in
		*function*) return;;
		*) eval "$1() { return; }"
	esac
}

_proto_do_teardown() {
	json_load "$data"
	eval "$1_teardown \"$interface\" \"$ifname\""
}

_proto_do_setup() {
	json_load "$data"
	_EXPORT_VAR=0
	_EXPORT_VARS=
	eval "$1_setup \"$interface\" \"$ifname\""
}

proto_init_update() {
	local ifname="$1"
	local up="$2"
	local external="$3"

	PROTO_INIT=1
	PROTO_IPADDR=
	PROTO_IP6ADDR=
	PROTO_ROUTE=
	PROTO_ROUTE6=
	json_init
	json_add_int action 0
	[ -n "$ifname" -a "*" != "$ifname" ] && json_add_string "ifname" "$ifname"
	json_add_boolean "link-up" "$up"
	[ -n "$3" ] && json_add_boolean "address-external" "$external"
}

proto_add_dns_server() {
	local address="$1"

	jshn_append PROTO_DNS "$address"
}

proto_add_dns_search() {
	local address="$1"

	jshn_append PROTO_DNS_SEARCH "$address"
}

proto_add_ipv4_address() {
	local address="$1"
	local mask="$2"

	jshn_append PROTO_IPADDR "$address/$mask"
}

proto_add_ipv6_address() {
	local address="$1"
	local mask="$2"

	jshn_append PROTO_IP6ADDR "$address/$mask"
}

proto_add_ipv4_route() {
	local target="$1"
	local mask="$2"
	local gw="$3"

	jshn_append PROTO_ROUTE "$target/$mask/$gw"
}

proto_add_ipv6_route() {
	local target="$1"
	local mask="$2"
	local gw="$3"

	jshn_append PROTO_ROUTE6 "$target/$mask/$gw"
}

_proto_push_ip() {
	json_add_string "" "$1"
}

_proto_push_route() {
	local str="$1";
	local target="${str%%/*}"
	str="${str#*/}"
	local mask="${str%%/*}"
	local gw="${str#*/}"

	json_add_table ""
	json_add_string target "$target"
	json_add_string mask "$mask"
	json_add_string gateway "$gw"
	json_close_table
}

_proto_push_array() {
	local name="$1"
	local val="$2"
	local cb="$3"

	[ -n "$val" ] || return 0
	json_add_array "$name"
	for item in $val; do
		eval "$cb \"\$item\""
	done
	json_close_array
}

_proto_notify() {
	local interface="$1"
	ubus call network.interface."$interface" notify_proto "$(json_dump)"
}

proto_send_update() {
	local interface="$1"

	_proto_push_array "ipaddr" "$PROTO_IPADDR" _proto_push_ip
	_proto_push_array "ip6addr" "$PROTO_IP6ADDR" _proto_push_ip
	_proto_push_array "route" "$PROTO_ROUTE" _proto_push_route
	_proto_push_array "route6" "$PROTO_ROUTE6" _proto_push_route
	_proto_push_array "dns" "$PROTO_DNS" _proto_push_ip
	_proto_push_array "dns_search" "$PROTO_DNS_SEARCH" _proto_push_ip
	_proto_notify "$interface"
}

proto_export() {
	local var="VAR${_EXPORT_VAR}"
	_EXPORT_VAR="$(($_EXPORT_VAR + 1))"
	export -- "$var=$1"
	jshn_append _EXPORT_VARS "$var"
}

proto_run_command() {
	local interface="$1"; shift

	json_init
	json_add_int action 1
	json_add_array command
	while [ $# -gt 0 ]; do
		json_add_string "" "$1"
		shift
	done
	json_close_array
	[ -n "$_EXPORT_VARS" ] && {
		json_add_array env
		for var in $_EXPORT_VARS; do
			eval "json_add_string \"\" \"\${$var}\""
		done
		json_close_array
	}
	_proto_notify "$interface"
}

proto_kill_command() {
	local interface="$1"; shift

	json_init
	json_add_int action 2
	[ -n "$1" ] && json_add_int signal "$1"
	_proto_notify "$interface"
}

init_proto() {
	proto="$1"; shift
	cmd="$1"; shift

	case "$cmd" in
		dump)
			add_protocol() {
				no_device=0
				available=0

				add_default_handler "$1_init_config"

				json_init
				json_add_string "name" "$1"
				eval "$1_init"
				json_add_boolean no-device "$no_device"
				json_add_boolean available "$available"
				json_add_array "config"
				eval "$1_init_config"
				json_close_array
				json_dump
			}
		;;
		setup|teardown)
			interface="$1"; shift
			data="$1"; shift
			ifname="$1"; shift

			add_protocol() {
				[[ "$proto" == "$1" ]] || return 0

				case "$cmd" in
					setup) _proto_do_setup "$1";;
					teardown) _proto_do_teardown "$1" ;;
					*) return 1 ;;
				esac
			}
		;;
	esac
}
