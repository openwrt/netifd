#!/bin/sh

CC="$1"
[ -n "$TARGET_CC_NOCACHE" ] && CC="$TARGET_CC_NOCACHE"

cat <<EOF
#include <linux/ethtool.h>

#define ETHTOOL_MODE_FULL(_speed, _mode) {					\\
	.speed = (_speed),							\\
	.bit_half = -1,								\\
	.bit_full = ETHTOOL_LINK_MODE_ ## _speed ## base ## _mode ## _Full_BIT,	\\
	.name = #_speed "base" #_mode,						\\
}

#define ETHTOOL_MODE_HALF(_speed, _mode) {					\\
	.speed = (_speed),							\\
	.bit_half = ETHTOOL_LINK_MODE_ ## _speed ## base ## _mode ## _Half_BIT,	\\
	.bit_full = -1,								\\
	.name = #_speed "base" #_mode,						\\
}

#define ETHTOOL_MODE_BOTH(_speed, _mode) {					\\
	.speed = (_speed),							\\
	.bit_half = ETHTOOL_LINK_MODE_ ## _speed ## base ## _mode ## _Half_BIT,	\\
	.bit_full = ETHTOOL_LINK_MODE_ ## _speed ## base ## _mode ## _Full_BIT,	\\
	.name = #_speed "base" #_mode,						\\
}

static const struct {
	unsigned int speed;
	int bit_half;
	int bit_full;
	const char *name;
} ethtool_modes[] = {
EOF

echo "#include <linux/ethtool.h>" | "$CC" -E - | \
	grep "ETHTOOL_LINK_MODE_[0-9]*base[A-Za-z0-9]*_...._BIT.*" | \
	sed -r 's/.*ETHTOOL_LINK_MODE_([0-9]*)base([A-Za-z0-9]*)_(....)_BIT.*/\1 \2 \3/' | \
	sort -u | LC_ALL=C sort -r -g | ( gothalf=0 ; while read speed mode duplex; do
		if [ "$duplex" = "Half" ]; then
			if [ "$gothalf" = "1" ]; then
				echo -e "$speed \tETHTOOL_MODE_HALF($p_speed, $p_mode),"
			fi
			gothalf=1
		elif [ "$duplex" = "Full" ]; then
			if [ "$gothalf" = "1" ]; then
				if [ "$p_speed" = "$speed" ] && [ "$p_mode" = "$mode" ]; then
					echo -e "$speed \tETHTOOL_MODE_BOTH($speed, $mode),"
				else
					echo -e "$p_speed \tETHTOOL_MODE_HALF($p_speed, $p_mode),"
					echo -e "$speed \tETHTOOL_MODE_FULL($speed, $mode),"
				fi
				gothalf=0
			else
				echo -e "$speed \tETHTOOL_MODE_FULL($speed, $mode),"
			fi
		else
			continue
		fi
		p_speed="$speed"
		p_mode="$mode"
		p_duplex="$duplex"
	done ; [ "$gothalf" = "1" ] && echo -e "$p_speed \tETHTOOL_MODE_HALF($p_speed, $p_mode)," ) | \
	LC_ALL=C sort -g | cut -d' ' -f2-
echo "};"
