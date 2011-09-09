. /usr/share/libubox/jshn.sh

proto_config_add_int() {
	json_add_int "$1" 5
}

proto_config_add_string() {
	json_add_int "$1" 3
}

proto_config_add_boolean() {
	json_add_int "$1" 7
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
			json_add_object "config"
			eval "$1_init_config"
			json_close_object
			json_dump
		}
	;;
	*)
		add_protocol() {
			return;
		}
	;;
esac
