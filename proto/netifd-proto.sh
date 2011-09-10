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

case "$1" in
	dump)
		add_protocol() {
			immediate=0

			add_default_handler "$1_init_config"

			json_init
			json_add_string "name" "$1"
			eval "$1_init"
			json_add_boolean immediate "$immediate"
			json_add_array "config"
			eval "$1_init_config"
			json_close_array
			json_dump
		}
	;;
	*)
		add_protocol() {
			return;
		}
	;;
esac
