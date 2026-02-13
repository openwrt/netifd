netifd.add_proto({
	name: "example",

	config: function(ctx) {
		return {
			server: ctx.uci.get("network", ctx.section, "server"),
		};
	},

	setup: function(proto) {
		proto.update_link(true, { ifname: proto.device });
	},

	teardown: function(proto) {
		proto.update_link(false);
	},
});
