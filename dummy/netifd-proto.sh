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

proto="$1"; shift
cmd="$1"; shift
interface="$1"; shift
data="$1"; shift
ifname="$1"; shift

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
	*)
		add_protocol() {
			[[ "$proto" == "$1" ]] || return 0

			case "$cmd" in
				setup) eval "$1_setup \"\$interface\" \"\$data\" \"\$ifname\"" ;;
				teardown) eval "$1_teardown \"\$interface\" \"\$data\" \"\$ifname\"" ;;
				*) return 1 ;;
			esac
		}
	;;
esac
