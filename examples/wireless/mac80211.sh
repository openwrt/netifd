#!/bin/sh
NETIFD_MAIN_DIR=../../scripts
. $NETIFD_MAIN_DIR/netifd-wireless.sh

init_wireless_driver "$@"

MP_CONFIG_INT="mesh_retry_timeout mesh_confirm_timeout mesh_holding_timeout mesh_max_peer_links
	       mesh_max_retries mesh_ttl mesh_element_ttl mesh_hwmp_max_preq_retries
	       mesh_path_refresh_time mesh_min_discovery_timeout mesh_hwmp_active_path_timeout
	       mesh_hwmp_preq_min_interval mesh_hwmp_net_diameter_traversal_time mesh_hwmp_rootmode
	       mesh_hwmp_rann_interval mesh_gate_announcements mesh_sync_offset_max_neighor
	       mesh_rssi_threshold mesh_hwmp_active_path_to_root_timeout mesh_hwmp_root_interval
	       mesh_hwmp_confirmation_interval mesh_awake_window mesh_plink_timeout"
MP_CONFIG_BOOL="mesh_auto_open_plinks mesh_fwding"
MP_CONFIG_STRING="mesh_power_mode"

hostapd_add_log_config() {
	config_add_boolean \
		log_80211 \
		log_8021x \
		log_radius \
		log_wpa \
		log_driver \
		log_iapp \
		log_mlme

	config_add_int log_level
}

hostapd_common_add_device_config() {
	config_add_array basic_rate
	config_add_array supported_rates
	config_add_string beacon_rate

	config_add_string country country3
	config_add_boolean country_ie doth
	config_add_boolean spectrum_mgmt_required
	config_add_int local_pwr_constraint
	config_add_string require_mode
	config_add_boolean legacy_rates
	config_add_int cell_density
	config_add_int rts_threshold
	config_add_int rssi_reject_assoc_rssi
	config_add_int rssi_ignore_probe_request
	config_add_int maxassoc
	config_add_int reg_power_type
	config_add_boolean stationary_ap

	config_add_string acs_chan_bias
	config_add_array hostapd_options

	config_add_int airtime_mode
	config_add_int mbssid

	config_add_boolean afc
	config_add_string \
		afc_request_version afc_request_id afc_serial_number \
		afc_location_type afc_location afc_height afc_height_type
	config_add_array afc_cert_ids afc_freq_range afc_op_class
	config_add_int \
		afc_min_power afc_major_axis afc_minor_axis afc_orientation \
		afc_vertical_tolerance

	hostapd_add_log_config
}


drv_mac80211_init_device_config() {
	hostapd_common_add_device_config

	config_add_string path phy 'macaddr:macaddr'
	config_add_string tx_burst
	config_add_string distance
	config_add_string ifname_prefix
	config_add_string macaddr_base
	config_add_int radio beacon_int chanbw frag rts
	config_add_int rxantenna txantenna txpower min_tx_power
	config_add_int num_global_macaddr multiple_bssid
	config_add_boolean noscan ht_coex acs_exclude_dfs background_radar
	config_add_array ht_capab
	config_add_array channels
	config_add_array scan_list
	config_add_boolean \
		rxldpc \
		short_gi_80 \
		short_gi_160 \
		tx_stbc_2by1 \
		su_beamformer \
		su_beamformee \
		mu_beamformer \
		mu_beamformee \
		he_su_beamformer \
		he_su_beamformee \
		he_mu_beamformer \
		vht_txop_ps \
		htc_vht \
		rx_antenna_pattern \
		tx_antenna_pattern \
		he_spr_sr_control \
		he_spr_psr_enabled \
		he_bss_color_enabled \
		he_twt_required
	config_add_int \
		beamformer_antennas \
		beamformee_antennas \
		vht_max_a_mpdu_len_exp \
		vht_max_mpdu \
		vht_link_adapt \
		vht160 \
		rx_stbc \
		tx_stbc \
		he_bss_color \
		he_spr_non_srg_obss_pd_max_offset
	config_add_boolean \
		ldpc \
		greenfield \
		short_gi_20 \
		short_gi_40 \
		max_amsdu \
		dsss_cck_40
}

hostapd_common_add_bss_config() {
	config_add_string 'bssid:macaddr' 'ssid:string'
	config_add_boolean wds wmm uapsd hidden utf8_ssid ppsk

	config_add_int maxassoc max_inactivity
	config_add_boolean disassoc_low_ack isolate short_preamble skip_inactivity_poll

	config_add_int \
		wep_rekey eap_reauth_period \
		wpa_group_rekey wpa_pair_rekey wpa_master_rekey
	config_add_boolean wpa_strict_rekey
	config_add_boolean wpa_disable_eapol_key_retries

	config_add_boolean tdls_prohibit

	config_add_boolean rsn_preauth auth_cache
	config_add_int ieee80211w
	config_add_int eapol_version

	config_add_array auth_server acct_server
	config_add_string 'server:host'
	config_add_string auth_secret key
	config_add_int 'auth_port:port' 'port:port'

	config_add_string acct_secret
	config_add_int acct_port
	config_add_int acct_interval

	config_add_int bss_load_update_period chan_util_avg_period

	config_add_string dae_client
	config_add_string dae_secret
	config_add_int dae_port

	config_add_string nasid
	config_add_string ownip
	config_add_string radius_client_addr
	config_add_string iapp_interface
	config_add_string eap_type ca_cert client_cert identity anonymous_identity auth priv_key priv_key_pwd
	config_add_boolean ca_cert_usesystem ca_cert2_usesystem
	config_add_string subject_match subject_match2
	config_add_array altsubject_match altsubject_match2
	config_add_array domain_match domain_match2 domain_suffix_match domain_suffix_match2
	config_add_string ieee80211w_mgmt_cipher

	config_add_int dynamic_vlan vlan_naming vlan_no_bridge
	config_add_string vlan_tagged_interface vlan_bridge
	config_add_string vlan_file

	config_add_string 'key1:wepkey' 'key2:wepkey' 'key3:wepkey' 'key4:wepkey' 'password:wpakey'

	config_add_string wpa_psk_file

	config_add_int multi_ap

	config_add_boolean wps_pushbutton wps_label ext_registrar wps_pbc_in_m1
	config_add_int wps_ap_setup_locked wps_independent
	config_add_string wps_device_type wps_device_name wps_manufacturer wps_pin
	config_add_string multi_ap_backhaul_ssid multi_ap_backhaul_key

	config_add_boolean wnm_sleep_mode wnm_sleep_mode_no_keys bss_transition mbo
	config_add_int time_advertisement
	config_add_string time_zone
	config_add_string vendor_elements

	config_add_boolean ieee80211k rrm_neighbor_report rrm_beacon_report

	config_add_boolean ftm_responder stationary_ap
	config_add_string lci civic

	config_add_boolean ieee80211r pmk_r1_push ft_psk_generate_local ft_over_ds
	config_add_int r0_key_lifetime reassociation_deadline
	config_add_string mobility_domain r1_key_holder rxkh_file
	config_add_array r0kh r1kh

	config_add_int ieee80211w_max_timeout ieee80211w_retry_timeout

	config_add_string macfilter 'macfile:file'
	config_add_array 'maclist:list(macaddr)'

	config_add_array bssid_blacklist
	config_add_array bssid_whitelist

	config_add_int mcast_rate
	config_add_array basic_rate
	config_add_array supported_rates

	config_add_boolean sae_require_mfp
	config_add_int sae_pwe

	config_add_string 'owe_transition_bssid:macaddr' 'owe_transition_ssid:string'
	config_add_string owe_transition_ifname

	config_add_boolean iw_enabled iw_internet iw_asra iw_esr iw_uesa
	config_add_int iw_access_network_type iw_venue_group iw_venue_type
	config_add_int iw_ipaddr_type_availability iw_gas_address3
	config_add_string iw_hessid iw_network_auth_type iw_qos_map_set
	config_add_array iw_roaming_consortium iw_domain_name iw_anqp_3gpp_cell_net iw_nai_realm
	config_add_array iw_anqp_elem iw_venue_name iw_venue_url

	config_add_boolean hs20 disable_dgaf osen
	config_add_int anqp_domain_id
	config_add_int hs20_deauth_req_timeout
	config_add_array hs20_oper_friendly_name
	config_add_array osu_provider
	config_add_array operator_icon
	config_add_array hs20_conn_capab
	config_add_string osu_ssid hs20_wan_metrics hs20_operating_class hs20_t_c_filename hs20_t_c_timestamp

	config_add_string hs20_t_c_server_url

	config_add_array airtime_sta_weight
	config_add_int airtime_bss_weight airtime_bss_limit

	config_add_boolean multicast_to_unicast multicast_to_unicast_all proxy_arp per_sta_vif

	config_add_array hostapd_bss_options
	config_add_boolean default_disabled

	config_add_boolean request_cui
	config_add_array radius_auth_req_attr
	config_add_array radius_acct_req_attr

	config_add_int eap_server radius_server_auth_port
	config_add_string eap_user_file ca_cert server_cert private_key private_key_passwd server_id radius_server_clients

	config_add_boolean fils
	config_add_string fils_dhcp

	config_add_int ocv

	config_add_boolean apup
	config_add_string apup_peer_ifname_prefix
}

drv_mac80211_init_iface_config() {
	hostapd_common_add_bss_config

	config_add_string 'macaddr:macaddr' ifname

	config_add_boolean wds powersave enable
	config_add_string wds_bridge
	config_add_int maxassoc
	config_add_int max_listen_int
	config_add_int dtim_period
	config_add_int start_disabled

	# mesh
	config_add_string mesh_id
	config_add_int $MP_CONFIG_INT
	config_add_boolean $MP_CONFIG_BOOL
	config_add_string $MP_CONFIG_STRING
}

setup_vif() {
	local name="$1"

	json_select config
	json_get_var ssid ssid
	json_select ..

	wireless_add_vif "$name" "${radio}v$vifidx"
	/bin/sleep 10 &
	wireless_add_process "$!" /bin/sleep 1
	vifidx=$((vifidx + 1))
}

drv_mac80211_cleanup() {
	echo "mac80211 cleanup"
}

drv_mac80211_setup() {
	echo "mac80211 setup: $1"
	radio=$1
	vifidx=0
	json_dump
	for_each_interface "sta ap adhoc" setup_vif
	wireless_set_data phy=phy0
	wireless_set_up
}

drv_mac80211_teardown() {
	json_select data
	json_get_var phy phy
	json_select ..
	echo "mac80211 teardown: $1 ($phy)"
	json_dump
}

add_driver mac80211
