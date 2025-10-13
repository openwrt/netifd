# Example: Applying ethtool tunables via /etc/config/network

You can specify ethtool flags for supported family (offload, ring, coalesce, channels, priv) in a device section of `/etc/config/network`.

> This doesn't replace existing flags already handled by netifd via ethtool (like `rxpause`, `txpause`, `autoneg`), it only adds support for additional ethtool tunables.

## Example device config

```
config device
    option name 'eth1'
    list offload 'sg on'
    list offload 'gso on'
    list offload 'gro on'
    list offload 'tso off'
    list offload 'rx_gro_list off'
    list offload 'rx_udp_gro_forwarding on'
    list ring 'rx 4096'
    list ring 'tx 4096'
    list coalesce 'rx-usecs 50'
    list coalesce 'tx-frames 128'
    list channels 'rx 4'
    list channels 'tx 4'
    list priv 'my_custom_flag on'
    option txqueuelen '10000'
```

## Supported ethtool tunable families

- `list offload` (ethtool -K)
- `list ring` (ethtool -G)
- `list coalesce` (ethtool -C)
- `list channels` (ethtool -L)
- `list priv` (ethtool --set-priv-flags)

Each list item is a key-value pair, e.g. `list offload 'tso off'`.

## How it works

- When netifd brings up the device, it parses these lists and applies them using the corresponding system_set_ethtool* handler (see `system-linux.c`).
- All settings are applied via netlink/ethtool, just as in the shell/init script, but natively in C.

## Notes

- You can specify multiple flags per family.
- If a flag is not supported by the driver, it will be ignored or logged as a warning.
- For advanced usage, refer to the system_set_ethtool* handlers in `system-linux.c` for details on what is supported.
