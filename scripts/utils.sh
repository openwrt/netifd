append() {
	local var="$1"
	local value="$2"
	local sep="${3:- }"

	eval "export -- \"$var=\${$var:+\${$var}\${value:+\$sep}}\$value\""
}

add_default_handler() {
	case "$(type $1 2>/dev/null)" in
		*function*) return;;
		*) eval "$1() { return; }"
	esac
}

_config_add_generic() {
	json_add_array ""
	json_add_string "" "$1"
	json_add_int "" "$2"
	json_close_array
}

config_add_int() {
	_config_add_generic "$1" 5
}

config_add_array() {
	_config_add_generic "$1" 1
}

config_add_string() {
	_config_add_generic "$1" 3
}

config_add_boolean() {
	_config_add_generic "$1" 7
}
