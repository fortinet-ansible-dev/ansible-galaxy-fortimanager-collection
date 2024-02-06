#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2024 Fortinet, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_switchcontroller_managedswitch
short_description: Configure FortiSwitch devices that are managed by this FortiGate.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Starting in version 2.4.0, all input arguments are named using the underscore naming convention (snake_case).
      Please change the arguments such as "var-name" to "var_name".
      Old argument names are still available yet you will receive deprecation warnings.
      You can ignore this warning by setting deprecation_warnings=False in ansible.cfg.
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded
options:
    access_token:
        description: The token to access FortiManager without using username and password.
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        elements: int
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        type: int
        default: 300
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    switchcontroller_managedswitch:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            _platform:
                type: str
                description: _Platform.
            description:
                type: str
                description: Description.
            name:
                type: str
                description: Managed-switch name.
                required: true
            ports:
                type: list
                elements: dict
                description: Ports.
                suboptions:
                    allowed-vlans:
                        type: raw
                        description: (list or str) Deprecated, please rename it to allowed_vlans. Configure switch port tagged vlans
                    allowed-vlans-all:
                        type: str
                        description: Deprecated, please rename it to allowed_vlans_all. Enable/disable all defined vlans on this port.
                        choices:
                            - 'disable'
                            - 'enable'
                    arp-inspection-trust:
                        type: str
                        description: Deprecated, please rename it to arp_inspection_trust. Trusted or untrusted dynamic ARP inspection.
                        choices:
                            - 'untrusted'
                            - 'trusted'
                    bundle:
                        type: str
                        description: Enable/disable Link Aggregation Group
                        choices:
                            - 'disable'
                            - 'enable'
                    description:
                        type: str
                        description: Description for port.
                    dhcp-snoop-option82-trust:
                        type: str
                        description: Deprecated, please rename it to dhcp_snoop_option82_trust. Enable/disable allowance of DHCP with option-82 on untr...
                        choices:
                            - 'disable'
                            - 'enable'
                    dhcp-snooping:
                        type: str
                        description: Deprecated, please rename it to dhcp_snooping. Trusted or untrusted DHCP-snooping interface.
                        choices:
                            - 'trusted'
                            - 'untrusted'
                    discard-mode:
                        type: str
                        description: Deprecated, please rename it to discard_mode. Configure discard mode for port.
                        choices:
                            - 'none'
                            - 'all-untagged'
                            - 'all-tagged'
                    edge-port:
                        type: str
                        description: Deprecated, please rename it to edge_port. Enable/disable this interface as an edge port, bridging connections bet...
                        choices:
                            - 'disable'
                            - 'enable'
                    igmp-snooping:
                        type: str
                        description: Deprecated, please rename it to igmp_snooping. Set IGMP snooping mode for the physical port interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps-flood-reports:
                        type: str
                        description: Deprecated, please rename it to igmps_flood_reports. Enable/disable flooding of IGMP reports to this interface whe...
                        choices:
                            - 'disable'
                            - 'enable'
                    igmps-flood-traffic:
                        type: str
                        description: Deprecated, please rename it to igmps_flood_traffic. Enable/disable flooding of IGMP snooping traffic to this inte...
                        choices:
                            - 'disable'
                            - 'enable'
                    lacp-speed:
                        type: str
                        description: Deprecated, please rename it to lacp_speed. End Link Aggregation Control Protocol
                        choices:
                            - 'slow'
                            - 'fast'
                    learning-limit:
                        type: int
                        description: Deprecated, please rename it to learning_limit. Limit the number of dynamic MAC addresses on this Port
                    lldp-profile:
                        type: str
                        description: Deprecated, please rename it to lldp_profile. LLDP port TLV profile.
                    lldp-status:
                        type: str
                        description: Deprecated, please rename it to lldp_status. LLDP transmit and receive status.
                        choices:
                            - 'disable'
                            - 'rx-only'
                            - 'tx-only'
                            - 'tx-rx'
                    loop-guard:
                        type: str
                        description: Deprecated, please rename it to loop_guard. Enable/disable loop-guard on this interface, an STP optimization used ...
                        choices:
                            - 'disabled'
                            - 'enabled'
                    loop-guard-timeout:
                        type: int
                        description: Deprecated, please rename it to loop_guard_timeout. Loop-guard timeout
                    max-bundle:
                        type: int
                        description: Deprecated, please rename it to max_bundle. Maximum size of LAG bundle
                    mclag:
                        type: str
                        description: Enable/disable multi-chassis link aggregation
                        choices:
                            - 'disable'
                            - 'enable'
                    member-withdrawal-behavior:
                        type: str
                        description: Deprecated, please rename it to member_withdrawal_behavior. Port behavior after it withdraws because of loss of co...
                        choices:
                            - 'forward'
                            - 'block'
                    members:
                        type: raw
                        description: (list) Aggregated LAG bundle interfaces.
                    min-bundle:
                        type: int
                        description: Deprecated, please rename it to min_bundle. Minimum size of LAG bundle
                    mode:
                        type: str
                        description: LACP mode
                        choices:
                            - 'static'
                            - 'lacp-passive'
                            - 'lacp-active'
                    poe-pre-standard-detection:
                        type: str
                        description: Deprecated, please rename it to poe_pre_standard_detection. Enable/disable PoE pre-standard detection.
                        choices:
                            - 'disable'
                            - 'enable'
                    poe-status:
                        type: str
                        description: Deprecated, please rename it to poe_status. Enable/disable PoE status.
                        choices:
                            - 'disable'
                            - 'enable'
                    port-name:
                        type: str
                        description: Deprecated, please rename it to port_name. Switch port name.
                    port-owner:
                        type: str
                        description: Deprecated, please rename it to port_owner. Switch port name.
                    port-security-policy:
                        type: str
                        description: Deprecated, please rename it to port_security_policy. Switch controller authentication policy to apply to this man...
                    port-selection-criteria:
                        type: str
                        description: Deprecated, please rename it to port_selection_criteria. Algorithm for aggregate port selection.
                        choices:
                            - 'src-mac'
                            - 'dst-mac'
                            - 'src-dst-mac'
                            - 'src-ip'
                            - 'dst-ip'
                            - 'src-dst-ip'
                    qos-policy:
                        type: str
                        description: Deprecated, please rename it to qos_policy. Switch controller QoS policy from available options.
                    sample-direction:
                        type: str
                        description: Deprecated, please rename it to sample_direction. SFlow sample direction.
                        choices:
                            - 'rx'
                            - 'tx'
                            - 'both'
                    sflow-counter-interval:
                        type: int
                        description: Deprecated, please rename it to sflow_counter_interval. SFlow sampler counter polling interval
                    sflow-sample-rate:
                        type: int
                        description: Deprecated, please rename it to sflow_sample_rate. SFlow sampler sample rate
                    sflow-sampler:
                        type: str
                        description: Deprecated, please rename it to sflow_sampler. Enable/disable sFlow protocol on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-bpdu-guard:
                        type: str
                        description: Deprecated, please rename it to stp_bpdu_guard. Enable/disable STP BPDU guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-bpdu-guard-timeout:
                        type: int
                        description: Deprecated, please rename it to stp_bpdu_guard_timeout. BPDU Guard disabling protection
                    stp-root-guard:
                        type: str
                        description: Deprecated, please rename it to stp_root_guard. Enable/disable STP root guard on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    stp-state:
                        type: str
                        description: Deprecated, please rename it to stp_state. Enable/disable Spanning Tree Protocol
                        choices:
                            - 'disabled'
                            - 'enabled'
                    type:
                        type: str
                        description: Interface type
                        choices:
                            - 'physical'
                            - 'trunk'
                    untagged-vlans:
                        type: raw
                        description: (list or str) Deprecated, please rename it to untagged_vlans. Configure switch port untagged vlans
                    vlan:
                        type: str
                        description: Assign switch ports to a VLAN.
                    export-to-pool-flag:
                        type: int
                        description: Deprecated, please rename it to export_to_pool_flag. Switch controller export port to pool-list.
                    mac-addr:
                        type: str
                        description: Deprecated, please rename it to mac_addr. Port/Trunk MAC.
                    packet-sample-rate:
                        type: int
                        description: Deprecated, please rename it to packet_sample_rate. Packet sampling rate
                    packet-sampler:
                        type: str
                        description: Deprecated, please rename it to packet_sampler. Enable/disable packet sampling on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    sticky-mac:
                        type: str
                        description: Deprecated, please rename it to sticky_mac. Enable or disable sticky-mac on the interface.
                        choices:
                            - 'disable'
                            - 'enable'
                    storm-control-policy:
                        type: str
                        description: Deprecated, please rename it to storm_control_policy. Switch controller storm control policy from available options.
                    dot1x-enable:
                        type: str
                        description: Deprecated, please rename it to dot1x_enable.
                        choices:
                            - 'disable'
                            - 'enable'
                    max-miss-heartbeats:
                        type: int
                        description: Deprecated, please rename it to max_miss_heartbeats. Maximum tolerant missed heartbeats.
                    access-mode:
                        type: str
                        description: Deprecated, please rename it to access_mode. Access mode of the port.
                        choices:
                            - 'normal'
                            - 'nac'
                            - 'dynamic'
                            - 'static'
                    ip-source-guard:
                        type: str
                        description: Deprecated, please rename it to ip_source_guard. Enable/disable IP source guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    mclag-icl-port:
                        type: int
                        description: Deprecated, please rename it to mclag_icl_port. Mclag-Icl-Port.
                    p2p-port:
                        type: int
                        description: Deprecated, please rename it to p2p_port. P2P-Port.
                    aggregator-mode:
                        type: str
                        description: Deprecated, please rename it to aggregator_mode. LACP member select mode.
                        choices:
                            - 'bandwidth'
                            - 'count'
                    rpvst-port:
                        type: str
                        description: Deprecated, please rename it to rpvst_port. Enable/disable inter-operability with rapid PVST on this interface.
                        choices:
                            - 'disabled'
                            - 'enabled'
                    flow-control:
                        type: str
                        description: Deprecated, please rename it to flow_control. Flow control direction.
                        choices:
                            - 'disable'
                            - 'tx'
                            - 'rx'
                            - 'both'
                    media-type:
                        type: str
                        description: Deprecated, please rename it to media_type. Media-Type.
                    pause-meter:
                        type: int
                        description: Deprecated, please rename it to pause_meter. Configure ingress pause metering rate, in kbps
                    pause-meter-resume:
                        type: str
                        description: Deprecated, please rename it to pause_meter_resume. Resume threshold for resuming traffic on ingress port.
                        choices:
                            - '25%'
                            - '50%'
                            - '75%'
                    trunk-member:
                        type: int
                        description: Deprecated, please rename it to trunk_member. Trunk member.
                    fec-capable:
                        type: int
                        description: Deprecated, please rename it to fec_capable. FEC capable.
                    fec-state:
                        type: str
                        description: Deprecated, please rename it to fec_state. State of forward error correction.
                        choices:
                            - 'disabled'
                            - 'cl74'
                            - 'cl91'
                            - 'detect-by-module'
                    matched-dpp-intf-tags:
                        type: str
                        description: Deprecated, please rename it to matched_dpp_intf_tags. Matched interface tags in the dynamic port policy.
                    matched-dpp-policy:
                        type: str
                        description: Deprecated, please rename it to matched_dpp_policy. Matched child policy in the dynamic port policy.
                    port-policy:
                        type: str
                        description: Deprecated, please rename it to port_policy. Switch controller dynamic port policy from available options.
                    status:
                        type: str
                        description: Switch port admin status
                        choices:
                            - 'down'
                            - 'up'
                    dsl-profile:
                        type: str
                        description: Deprecated, please rename it to dsl_profile. DSL policy configuration.
                    flap-duration:
                        type: int
                        description: Deprecated, please rename it to flap_duration. Period over which flap events are calculated
                    flap-rate:
                        type: int
                        description: Deprecated, please rename it to flap_rate. Number of stage change events needed within flap-duration.
                    flap-timeout:
                        type: int
                        description: Deprecated, please rename it to flap_timeout. Flap guard disabling protection
                    flapguard:
                        type: str
                        description: Enable/disable flap guard.
                        choices:
                            - 'disable'
                            - 'enable'
                    interface-tags:
                        type: raw
                        description: (list or str) Deprecated, please rename it to interface_tags.
                    poe-max-power:
                        type: str
                        description: Deprecated, please rename it to poe_max_power.
                    poe-standard:
                        type: str
                        description: Deprecated, please rename it to poe_standard.
                    igmp-snooping-flood-reports:
                        type: str
                        description: Deprecated, please rename it to igmp_snooping_flood_reports. Enable/disable flooding of IGMP reports to this inter...
                        choices:
                            - 'disable'
                            - 'enable'
                    mcast-snooping-flood-traffic:
                        type: str
                        description: Deprecated, please rename it to mcast_snooping_flood_traffic. Enable/disable flooding of IGMP snooping traffic to ...
                        choices:
                            - 'disable'
                            - 'enable'
                    link-status:
                        type: str
                        description: Deprecated, please rename it to link_status.
                        choices:
                            - 'down'
                            - 'up'
                    poe-mode-bt-cabable:
                        type: int
                        description: Deprecated, please rename it to poe_mode_bt_cabable. PoE mode IEEE 802.
                    poe-port-mode:
                        type: str
                        description: Deprecated, please rename it to poe_port_mode. Configure PoE port mode.
                        choices:
                            - 'ieee802-3af'
                            - 'ieee802-3at'
                            - 'ieee802-3bt'
                    poe-port-power:
                        type: str
                        description: Deprecated, please rename it to poe_port_power. Configure PoE port power.
                        choices:
                            - 'normal'
                            - 'perpetual'
                            - 'perpetual-fast'
                    poe-port-priority:
                        type: str
                        description: Deprecated, please rename it to poe_port_priority. Configure PoE port priority.
                        choices:
                            - 'critical-priority'
                            - 'high-priority'
                            - 'low-priority'
                            - 'medium-priority'
                    acl-group:
                        type: raw
                        description: (list) Deprecated, please rename it to acl_group.
                    dhcp-snoop-option82-override:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to dhcp_snoop_option82_override.
                        suboptions:
                            circuit-id:
                                type: str
                                description: Deprecated, please rename it to circuit_id. Circuit ID string.
                            remote-id:
                                type: str
                                description: Deprecated, please rename it to remote_id. Remote ID string.
                            vlan-name:
                                type: str
                                description: Deprecated, please rename it to vlan_name. DHCP snooping option 82 VLAN.
                    fortiswitch-acls:
                        type: raw
                        description: (list) Deprecated, please rename it to fortiswitch_acls.
                    isl-peer-device-sn:
                        type: str
                        description: Deprecated, please rename it to isl_peer_device_sn.
                    authenticated-port:
                        type: int
                        description: Deprecated, please rename it to authenticated_port.
                    encrypted-port:
                        type: int
                        description: Deprecated, please rename it to encrypted_port.
                    ptp-status:
                        type: str
                        description: Deprecated, please rename it to ptp_status. Enable/disable PTP policy on this FortiSwitch port.
                        choices:
                            - 'disable'
                            - 'enable'
                    restricted-auth-port:
                        type: int
                        description: Deprecated, please rename it to restricted_auth_port.
            switch-id:
                type: str
                description: Deprecated, please rename it to switch_id. Managed-switch id.
            override-snmp-community:
                type: str
                description: Deprecated, please rename it to override_snmp_community. Enable/disable overriding the global SNMP communities.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-sysinfo:
                type: str
                description: Deprecated, please rename it to override_snmp_sysinfo. Enable/disable overriding the global SNMP system information.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-trap-threshold:
                type: str
                description: Deprecated, please rename it to override_snmp_trap_threshold. Enable/disable overriding the global SNMP trap threshold values.
                choices:
                    - 'disable'
                    - 'enable'
            override-snmp-user:
                type: str
                description: Deprecated, please rename it to override_snmp_user. Enable/disable overriding the global SNMP users.
                choices:
                    - 'disable'
                    - 'enable'
            poe-detection-type:
                type: int
                description: Deprecated, please rename it to poe_detection_type. Poe-Detection-Type.
            remote-log:
                type: list
                elements: dict
                description: Deprecated, please rename it to remote_log.
                suboptions:
                    csv:
                        type: str
                        description: Enable/disable comma-separated value
                        choices:
                            - 'disable'
                            - 'enable'
                    facility:
                        type: str
                        description: Facility to log to remote syslog server.
                        choices:
                            - 'kernel'
                            - 'user'
                            - 'mail'
                            - 'daemon'
                            - 'auth'
                            - 'syslog'
                            - 'lpr'
                            - 'news'
                            - 'uucp'
                            - 'cron'
                            - 'authpriv'
                            - 'ftp'
                            - 'ntp'
                            - 'audit'
                            - 'alert'
                            - 'clock'
                            - 'local0'
                            - 'local1'
                            - 'local2'
                            - 'local3'
                            - 'local4'
                            - 'local5'
                            - 'local6'
                            - 'local7'
                    name:
                        type: str
                        description: Remote log name.
                    port:
                        type: int
                        description: Remote syslog server listening port.
                    server:
                        type: str
                        description: IPv4 address of the remote syslog server.
                    severity:
                        type: str
                        description: Severity of logs to be transferred to remote log server.
                        choices:
                            - 'emergency'
                            - 'alert'
                            - 'critical'
                            - 'error'
                            - 'warning'
                            - 'notification'
                            - 'information'
                            - 'debug'
                    status:
                        type: str
                        description: Enable/disable logging by FortiSwitch device to a remote syslog server.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp-community:
                type: list
                elements: dict
                description: Deprecated, please rename it to snmp_community.
                suboptions:
                    events:
                        type: list
                        elements: str
                        description: No description.
                        choices:
                            - 'cpu-high'
                            - 'mem-low'
                            - 'log-full'
                            - 'intf-ip'
                            - 'ent-conf-change'
                    hosts:
                        type: list
                        elements: dict
                        description: No description.
                        suboptions:
                            id:
                                type: int
                                description: Host entry ID.
                            ip:
                                type: str
                                description: IPv4 address of the SNMP manager
                    id:
                        type: int
                        description: SNMP community ID.
                    name:
                        type: str
                        description: SNMP community name.
                    query-v1-port:
                        type: int
                        description: Deprecated, please rename it to query_v1_port. SNMP v1 query port
                    query-v1-status:
                        type: str
                        description: Deprecated, please rename it to query_v1_status. Enable/disable SNMP v1 queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    query-v2c-port:
                        type: int
                        description: Deprecated, please rename it to query_v2c_port. SNMP v2c query port
                    query-v2c-status:
                        type: str
                        description: Deprecated, please rename it to query_v2c_status. Enable/disable SNMP v2c queries.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Enable/disable this SNMP community.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap-v1-lport:
                        type: int
                        description: Deprecated, please rename it to trap_v1_lport. SNMP v2c trap local port
                    trap-v1-rport:
                        type: int
                        description: Deprecated, please rename it to trap_v1_rport. SNMP v2c trap remote port
                    trap-v1-status:
                        type: str
                        description: Deprecated, please rename it to trap_v1_status. Enable/disable SNMP v1 traps.
                        choices:
                            - 'disable'
                            - 'enable'
                    trap-v2c-lport:
                        type: int
                        description: Deprecated, please rename it to trap_v2c_lport. SNMP v2c trap local port
                    trap-v2c-rport:
                        type: int
                        description: Deprecated, please rename it to trap_v2c_rport. SNMP v2c trap remote port
                    trap-v2c-status:
                        type: str
                        description: Deprecated, please rename it to trap_v2c_status. Enable/disable SNMP v2c traps.
                        choices:
                            - 'disable'
                            - 'enable'
            snmp-user:
                type: list
                elements: dict
                description: Deprecated, please rename it to snmp_user.
                suboptions:
                    auth-proto:
                        type: str
                        description: Deprecated, please rename it to auth_proto. Authentication protocol.
                        choices:
                            - 'md5'
                            - 'sha'
                    auth-pwd:
                        type: raw
                        description: (list) Deprecated, please rename it to auth_pwd.
                    name:
                        type: str
                        description: SNMP user name.
                    priv-proto:
                        type: str
                        description: Deprecated, please rename it to priv_proto. Privacy
                        choices:
                            - 'des'
                            - 'aes'
                    priv-pwd:
                        type: raw
                        description: (list) Deprecated, please rename it to priv_pwd.
                    queries:
                        type: str
                        description: Enable/disable SNMP queries for this user.
                        choices:
                            - 'disable'
                            - 'enable'
                    query-port:
                        type: int
                        description: Deprecated, please rename it to query_port. SNMPv3 query port
                    security-level:
                        type: str
                        description: Deprecated, please rename it to security_level. Security level for message authentication and encryption.
                        choices:
                            - 'no-auth-no-priv'
                            - 'auth-no-priv'
                            - 'auth-priv'
            mclag-igmp-snooping-aware:
                type: str
                description: Deprecated, please rename it to mclag_igmp_snooping_aware. Enable/disable MCLAG IGMP-snooping awareness.
                choices:
                    - 'disable'
                    - 'enable'
            ip-source-guard:
                type: list
                elements: dict
                description: Deprecated, please rename it to ip_source_guard.
                suboptions:
                    binding-entry:
                        type: list
                        elements: dict
                        description: Deprecated, please rename it to binding_entry.
                        suboptions:
                            entry-name:
                                type: str
                                description: Deprecated, please rename it to entry_name. Configure binding pair.
                            ip:
                                type: str
                                description: Source IP for this rule.
                            mac:
                                type: str
                                description: MAC address for this rule.
                    description:
                        type: str
                        description: Description.
                    port:
                        type: str
                        description: Ingress interface to which source guard is bound.
            l3-discovered:
                type: int
                description: Deprecated, please rename it to l3_discovered. L3-Discovered.
            qos-drop-policy:
                type: str
                description: Deprecated, please rename it to qos_drop_policy. Set QoS drop-policy.
                choices:
                    - 'taildrop'
                    - 'random-early-detection'
            qos-red-probability:
                type: int
                description: Deprecated, please rename it to qos_red_probability. Set QoS RED/WRED drop probability.
            switch-dhcp_opt43_key:
                type: str
                description: Deprecated, please rename it to switch_dhcp_opt43_key. DHCP option43 key.
            tdr-supported:
                type: str
                description: Deprecated, please rename it to tdr_supported. Tdr-Supported.
            custom-command:
                type: list
                elements: dict
                description: Deprecated, please rename it to custom_command. Custom-Command.
                suboptions:
                    command-entry:
                        type: str
                        description: Deprecated, please rename it to command_entry. List of FortiSwitch commands.
                    command-name:
                        type: str
                        description: Deprecated, please rename it to command_name. Names of commands to be pushed to this FortiSwitch device, as config...
            firmware-provision:
                type: str
                description: Deprecated, please rename it to firmware_provision. Enable/disable provisioning of firmware to FortiSwitches on join conne...
                choices:
                    - 'disable'
                    - 'enable'
            firmware-provision-version:
                type: str
                description: Deprecated, please rename it to firmware_provision_version. Firmware version to provision to this FortiSwitch on bootup
            dhcp-server-access-list:
                type: str
                description: Deprecated, please rename it to dhcp_server_access_list. DHCP snooping server access list.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'global'
            firmware-provision-latest:
                type: str
                description: Deprecated, please rename it to firmware_provision_latest. Enable/disable one-time automatic provisioning of the latest fi...
                choices:
                    - 'disable'
                    - 'once'
            dhcp-snooping-static-client:
                type: list
                elements: dict
                description: Deprecated, please rename it to dhcp_snooping_static_client.
                suboptions:
                    ip:
                        type: str
                        description: Client static IP address.
                    mac:
                        type: str
                        description: Client MAC address.
                    name:
                        type: str
                        description: Client name.
                    port:
                        type: str
                        description: Interface name.
                    vlan:
                        type: str
                        description: VLAN name.
            ptp-profile:
                type: str
                description: Deprecated, please rename it to ptp_profile. PTP profile configuration.
            ptp-status:
                type: str
                description: Deprecated, please rename it to ptp_status. Enable/disable PTP profile on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route-offload:
                type: str
                description: Deprecated, please rename it to route_offload. Enable/disable route offload on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route-offload-mclag:
                type: str
                description: Deprecated, please rename it to route_offload_mclag. Enable/disable route offload MCLAG on this FortiSwitch.
                choices:
                    - 'disable'
                    - 'enable'
            route-offload-router:
                type: list
                elements: dict
                description: Deprecated, please rename it to route_offload_router.
                suboptions:
                    router-ip:
                        type: str
                        description: Deprecated, please rename it to router_ip. Router IP address.
                    vlan-name:
                        type: str
                        description: Deprecated, please rename it to vlan_name. VLAN name.
            mgmt-mode:
                type: int
                description: Deprecated, please rename it to mgmt_mode. FortiLink management mode.
            purdue-level:
                type: str
                description: Deprecated, please rename it to purdue_level. Purdue Level of this FortiSwitch.
                choices:
                    - '1'
                    - '2'
                    - '3'
                    - '4'
                    - '5'
                    - '1.5'
                    - '2.5'
                    - '3.5'
                    - '5.5'
            radius-nas-ip:
                type: str
                description: Deprecated, please rename it to radius_nas_ip. NAS-IP address.
            radius-nas-ip-override:
                type: str
                description: Deprecated, please rename it to radius_nas_ip_override. Use locally defined NAS-IP.
                choices:
                    - 'disable'
                    - 'enable'
            tunnel-discovered:
                type: int
                description: Deprecated, please rename it to tunnel_discovered.
            vlan:
                type: list
                elements: dict
                description: No description.
                suboptions:
                    assignment-priority:
                        type: int
                        description: Deprecated, please rename it to assignment_priority. '802.'
                    vlan-name:
                        type: str
                        description: Deprecated, please rename it to vlan_name. VLAN name.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure FortiSwitch devices that are managed by this FortiGate.
      fortinet.fortimanager.fmgr_switchcontroller_managedswitch:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        state: present # <value in [present, absent]>
        switchcontroller_managedswitch:
          _platform: <string>
          description: <string>
          name: <string>
          ports:
            -
              allowed_vlans: <list or string>
              allowed_vlans_all: <value in [disable, enable]>
              arp_inspection_trust: <value in [untrusted, trusted]>
              bundle: <value in [disable, enable]>
              description: <string>
              dhcp_snoop_option82_trust: <value in [disable, enable]>
              dhcp_snooping: <value in [trusted, untrusted]>
              discard_mode: <value in [none, all-untagged, all-tagged]>
              edge_port: <value in [disable, enable]>
              igmp_snooping: <value in [disable, enable]>
              igmps_flood_reports: <value in [disable, enable]>
              igmps_flood_traffic: <value in [disable, enable]>
              lacp_speed: <value in [slow, fast]>
              learning_limit: <integer>
              lldp_profile: <string>
              lldp_status: <value in [disable, rx-only, tx-only, ...]>
              loop_guard: <value in [disabled, enabled]>
              loop_guard_timeout: <integer>
              max_bundle: <integer>
              mclag: <value in [disable, enable]>
              member_withdrawal_behavior: <value in [forward, block]>
              members: <list or string>
              min_bundle: <integer>
              mode: <value in [static, lacp-passive, lacp-active]>
              poe_pre_standard_detection: <value in [disable, enable]>
              poe_status: <value in [disable, enable]>
              port_name: <string>
              port_owner: <string>
              port_security_policy: <string>
              port_selection_criteria: <value in [src-mac, dst-mac, src-dst-mac, ...]>
              qos_policy: <string>
              sample_direction: <value in [rx, tx, both]>
              sflow_counter_interval: <integer>
              sflow_sample_rate: <integer>
              sflow_sampler: <value in [disabled, enabled]>
              stp_bpdu_guard: <value in [disabled, enabled]>
              stp_bpdu_guard_timeout: <integer>
              stp_root_guard: <value in [disabled, enabled]>
              stp_state: <value in [disabled, enabled]>
              type: <value in [physical, trunk]>
              untagged_vlans: <list or string>
              vlan: <string>
              export_to_pool_flag: <integer>
              mac_addr: <string>
              packet_sample_rate: <integer>
              packet_sampler: <value in [disabled, enabled]>
              sticky_mac: <value in [disable, enable]>
              storm_control_policy: <string>
              dot1x_enable: <value in [disable, enable]>
              max_miss_heartbeats: <integer>
              access_mode: <value in [normal, nac, dynamic, ...]>
              ip_source_guard: <value in [disable, enable]>
              mclag_icl_port: <integer>
              p2p_port: <integer>
              aggregator_mode: <value in [bandwidth, count]>
              rpvst_port: <value in [disabled, enabled]>
              flow_control: <value in [disable, tx, rx, ...]>
              media_type: <string>
              pause_meter: <integer>
              pause_meter_resume: <value in [25%, 50%, 75%]>
              trunk_member: <integer>
              fec_capable: <integer>
              fec_state: <value in [disabled, cl74, cl91, ...]>
              matched_dpp_intf_tags: <string>
              matched_dpp_policy: <string>
              port_policy: <string>
              status: <value in [down, up]>
              dsl_profile: <string>
              flap_duration: <integer>
              flap_rate: <integer>
              flap_timeout: <integer>
              flapguard: <value in [disable, enable]>
              interface_tags: <list or string>
              poe_max_power: <string>
              poe_standard: <string>
              igmp_snooping_flood_reports: <value in [disable, enable]>
              mcast_snooping_flood_traffic: <value in [disable, enable]>
              link_status: <value in [down, up]>
              poe_mode_bt_cabable: <integer>
              poe_port_mode: <value in [ieee802-3af, ieee802-3at, ieee802-3bt]>
              poe_port_power: <value in [normal, perpetual, perpetual-fast]>
              poe_port_priority: <value in [critical-priority, high-priority, low-priority, ...]>
              acl_group: <list or string>
              dhcp_snoop_option82_override:
                -
                  circuit_id: <string>
                  remote_id: <string>
                  vlan_name: <string>
              fortiswitch_acls: <list or integer>
              isl_peer_device_sn: <string>
              authenticated_port: <integer>
              encrypted_port: <integer>
              ptp_status: <value in [disable, enable]>
              restricted_auth_port: <integer>
          switch_id: <string>
          override_snmp_community: <value in [disable, enable]>
          override_snmp_sysinfo: <value in [disable, enable]>
          override_snmp_trap_threshold: <value in [disable, enable]>
          override_snmp_user: <value in [disable, enable]>
          poe_detection_type: <integer>
          remote_log:
            -
              csv: <value in [disable, enable]>
              facility: <value in [kernel, user, mail, ...]>
              name: <string>
              port: <integer>
              server: <string>
              severity: <value in [emergency, alert, critical, ...]>
              status: <value in [disable, enable]>
          snmp_community:
            -
              events:
                - cpu-high
                - mem-low
                - log-full
                - intf-ip
                - ent-conf-change
              hosts:
                -
                  id: <integer>
                  ip: <string>
              id: <integer>
              name: <string>
              query_v1_port: <integer>
              query_v1_status: <value in [disable, enable]>
              query_v2c_port: <integer>
              query_v2c_status: <value in [disable, enable]>
              status: <value in [disable, enable]>
              trap_v1_lport: <integer>
              trap_v1_rport: <integer>
              trap_v1_status: <value in [disable, enable]>
              trap_v2c_lport: <integer>
              trap_v2c_rport: <integer>
              trap_v2c_status: <value in [disable, enable]>
          snmp_user:
            -
              auth_proto: <value in [md5, sha]>
              auth_pwd: <list or string>
              name: <string>
              priv_proto: <value in [des, aes]>
              priv_pwd: <list or string>
              queries: <value in [disable, enable]>
              query_port: <integer>
              security_level: <value in [no-auth-no-priv, auth-no-priv, auth-priv]>
          mclag_igmp_snooping_aware: <value in [disable, enable]>
          ip_source_guard:
            -
              binding_entry:
                -
                  entry_name: <string>
                  ip: <string>
                  mac: <string>
              description: <string>
              port: <string>
          l3_discovered: <integer>
          qos_drop_policy: <value in [taildrop, random-early-detection]>
          qos_red_probability: <integer>
          switch_dhcp_opt43_key: <string>
          tdr_supported: <string>
          custom_command:
            -
              command_entry: <string>
              command_name: <string>
          firmware_provision: <value in [disable, enable]>
          firmware_provision_version: <string>
          dhcp_server_access_list: <value in [disable, enable, global]>
          firmware_provision_latest: <value in [disable, once]>
          dhcp_snooping_static_client:
            -
              ip: <string>
              mac: <string>
              name: <string>
              port: <string>
              vlan: <string>
          ptp_profile: <string>
          ptp_status: <value in [disable, enable]>
          route_offload: <value in [disable, enable]>
          route_offload_mclag: <value in [disable, enable]>
          route_offload_router:
            -
              router_ip: <string>
              vlan_name: <string>
          mgmt_mode: <integer>
          purdue_level: <value in [1, 2, 3, ...]>
          radius_nas_ip: <string>
          radius_nas_ip_override: <value in [disable, enable]>
          tunnel_discovered: <integer>
          vlan:
            -
              assignment_priority: <integer>
              vlan_name: <string>
'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch',
        '/pm/config/global/obj/switch-controller/managed-switch'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/switch-controller/managed-switch/{managed-switch}',
        '/pm/config/global/obj/switch-controller/managed-switch/{managed-switch}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'switchcontroller_managedswitch': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                '_platform': {'type': 'str'},
                'description': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'ports': {
                    'type': 'list',
                    'options': {
                        'allowed-vlans': {'type': 'raw'},
                        'allowed-vlans-all': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'arp-inspection-trust': {'choices': ['untrusted', 'trusted'], 'type': 'str'},
                        'bundle': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'description': {'type': 'str'},
                        'dhcp-snoop-option82-trust': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'dhcp-snooping': {'choices': ['trusted', 'untrusted'], 'type': 'str'},
                        'discard-mode': {'choices': ['none', 'all-untagged', 'all-tagged'], 'type': 'str'},
                        'edge-port': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmp-snooping': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmps-flood-reports': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'igmps-flood-traffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'lacp-speed': {'choices': ['slow', 'fast'], 'type': 'str'},
                        'learning-limit': {'type': 'int'},
                        'lldp-profile': {'type': 'str'},
                        'lldp-status': {'choices': ['disable', 'rx-only', 'tx-only', 'tx-rx'], 'type': 'str'},
                        'loop-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'loop-guard-timeout': {'type': 'int'},
                        'max-bundle': {'type': 'int'},
                        'mclag': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'member-withdrawal-behavior': {'choices': ['forward', 'block'], 'type': 'str'},
                        'members': {'type': 'raw'},
                        'min-bundle': {'type': 'int'},
                        'mode': {'choices': ['static', 'lacp-passive', 'lacp-active'], 'type': 'str'},
                        'poe-pre-standard-detection': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'poe-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                        'port-name': {'type': 'str'},
                        'port-owner': {'type': 'str'},
                        'port-security-policy': {'type': 'str'},
                        'port-selection-criteria': {'choices': ['src-mac', 'dst-mac', 'src-dst-mac', 'src-ip', 'dst-ip', 'src-dst-ip'], 'type': 'str'},
                        'qos-policy': {'type': 'str'},
                        'sample-direction': {'choices': ['rx', 'tx', 'both'], 'type': 'str'},
                        'sflow-counter-interval': {'type': 'int'},
                        'sflow-sample-rate': {'v_range': [['6.0.0', '7.2.1']], 'type': 'int'},
                        'sflow-sampler': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-bpdu-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-bpdu-guard-timeout': {'type': 'int'},
                        'stp-root-guard': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'stp-state': {'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'type': {'choices': ['physical', 'trunk'], 'type': 'str'},
                        'untagged-vlans': {'type': 'raw'},
                        'vlan': {'type': 'str'},
                        'export-to-pool-flag': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'mac-addr': {'v_range': [['6.2.1', '6.2.1']], 'type': 'str'},
                        'packet-sample-rate': {'v_range': [['6.2.0', '']], 'type': 'int'},
                        'packet-sampler': {'v_range': [['6.2.0', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'sticky-mac': {'v_range': [['6.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'storm-control-policy': {'v_range': [['6.2.0', '6.2.3']], 'type': 'str'},
                        'dot1x-enable': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'max-miss-heartbeats': {'v_range': [['6.2.0', '6.2.12']], 'type': 'int'},
                        'access-mode': {'v_range': [['6.4.0', '']], 'choices': ['normal', 'nac', 'dynamic', 'static'], 'type': 'str'},
                        'ip-source-guard': {'v_range': [['6.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mclag-icl-port': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'p2p-port': {'v_range': [['6.4.0', '']], 'type': 'int'},
                        'aggregator-mode': {'v_range': [['6.4.2', '']], 'choices': ['bandwidth', 'count'], 'type': 'str'},
                        'rpvst-port': {'v_range': [['6.4.2', '']], 'choices': ['disabled', 'enabled'], 'type': 'str'},
                        'flow-control': {'v_range': [['6.4.3', '']], 'choices': ['disable', 'tx', 'rx', 'both'], 'type': 'str'},
                        'media-type': {'v_range': [['6.4.3', '']], 'type': 'str'},
                        'pause-meter': {'v_range': [['6.4.3', '']], 'type': 'int'},
                        'pause-meter-resume': {'v_range': [['6.4.3', '']], 'choices': ['25%', '50%', '75%'], 'type': 'str'},
                        'trunk-member': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                        'fec-capable': {'v_range': [['7.0.0', '']], 'type': 'int'},
                        'fec-state': {'v_range': [['7.0.0', '']], 'choices': ['disabled', 'cl74', 'cl91', 'detect-by-module'], 'type': 'str'},
                        'matched-dpp-intf-tags': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'matched-dpp-policy': {'v_range': [['7.0.0', '']], 'type': 'str'},
                        'port-policy': {'v_range': [['7.0.0', '7.0.4'], ['7.2.0', '']], 'type': 'str'},
                        'status': {'v_range': [['6.4.6', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'dsl-profile': {'v_range': [['7.0.2', '']], 'type': 'str'},
                        'flap-duration': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flap-rate': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flap-timeout': {'v_range': [['7.2.0', '']], 'type': 'int'},
                        'flapguard': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'interface-tags': {'v_range': [['7.0.2', '']], 'type': 'raw'},
                        'poe-max-power': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'poe-standard': {'v_range': [['7.0.1', '']], 'type': 'str'},
                        'igmp-snooping-flood-reports': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mcast-snooping-flood-traffic': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'link-status': {'v_range': [['7.2.2', '']], 'choices': ['down', 'up'], 'type': 'str'},
                        'poe-mode-bt-cabable': {'v_range': [['7.2.2', '']], 'type': 'int'},
                        'poe-port-mode': {'v_range': [['7.2.2', '']], 'choices': ['ieee802-3af', 'ieee802-3at', 'ieee802-3bt'], 'type': 'str'},
                        'poe-port-power': {'v_range': [['7.2.2', '']], 'choices': ['normal', 'perpetual', 'perpetual-fast'], 'type': 'str'},
                        'poe-port-priority': {
                            'v_range': [['7.2.2', '']],
                            'choices': ['critical-priority', 'high-priority', 'low-priority', 'medium-priority'],
                            'type': 'str'
                        },
                        'acl-group': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                        'dhcp-snoop-option82-override': {
                            'v_range': [['7.4.0', '']],
                            'type': 'list',
                            'options': {
                                'circuit-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                                'remote-id': {'v_range': [['7.4.0', '']], 'type': 'str'},
                                'vlan-name': {'v_range': [['7.4.0', '']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'fortiswitch-acls': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                        'isl-peer-device-sn': {'v_range': [['7.4.0', '']], 'type': 'str'},
                        'authenticated-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'encrypted-port': {'v_range': [['7.4.1', '']], 'type': 'int'},
                        'ptp-status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'restricted-auth-port': {'v_range': [['7.4.1', '']], 'type': 'int'}
                    },
                    'elements': 'dict'
                },
                'switch-id': {'type': 'str'},
                'override-snmp-community': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-sysinfo': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-trap-threshold': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'override-snmp-user': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'poe-detection-type': {'v_range': [['6.2.0', '']], 'type': 'int'},
                'remote-log': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'type': 'list',
                    'options': {
                        'csv': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'facility': {
                            'v_range': [['6.2.1', '6.2.3']],
                            'choices': [
                                'kernel', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit',
                                'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'
                            ],
                            'type': 'str'
                        },
                        'name': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'},
                        'port': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'server': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'},
                        'severity': {
                            'v_range': [['6.2.1', '6.2.3']],
                            'choices': ['emergency', 'alert', 'critical', 'error', 'warning', 'notification', 'information', 'debug'],
                            'type': 'str'
                        },
                        'status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'snmp-community': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'type': 'list',
                    'options': {
                        'events': {
                            'v_range': [['6.2.1', '6.2.3']],
                            'type': 'list',
                            'choices': ['cpu-high', 'mem-low', 'log-full', 'intf-ip', 'ent-conf-change'],
                            'elements': 'str'
                        },
                        'hosts': {
                            'v_range': [['6.2.1', '6.2.3']],
                            'type': 'list',
                            'options': {'id': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'}, 'ip': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'}},
                            'elements': 'dict'
                        },
                        'id': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'name': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'},
                        'query-v1-port': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'query-v1-status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'query-v2c-port': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'query-v2c-status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v1-lport': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'trap-v1-rport': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'trap-v1-status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'trap-v2c-lport': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'trap-v2c-rport': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'trap-v2c-status': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'snmp-user': {
                    'v_range': [['6.2.1', '6.2.3']],
                    'type': 'list',
                    'options': {
                        'auth-proto': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['md5', 'sha'], 'type': 'str'},
                        'auth-pwd': {'v_range': [['6.2.1', '6.2.3']], 'type': 'raw'},
                        'name': {'v_range': [['6.2.1', '6.2.3']], 'type': 'str'},
                        'priv-proto': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['des', 'aes'], 'type': 'str'},
                        'priv-pwd': {'v_range': [['6.2.1', '6.2.3']], 'type': 'raw'},
                        'queries': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'query-port': {'v_range': [['6.2.1', '6.2.3']], 'type': 'int'},
                        'security-level': {'v_range': [['6.2.1', '6.2.3']], 'choices': ['no-auth-no-priv', 'auth-no-priv', 'auth-priv'], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'mclag-igmp-snooping-aware': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-source-guard': {
                    'v_range': [['6.4.0', '6.4.1']],
                    'type': 'list',
                    'options': {
                        'binding-entry': {
                            'v_range': [['6.4.0', '6.4.1']],
                            'type': 'list',
                            'options': {
                                'entry-name': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'},
                                'ip': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'},
                                'mac': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'}
                            },
                            'elements': 'dict'
                        },
                        'description': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'},
                        'port': {'v_range': [['6.4.0', '6.4.1']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'l3-discovered': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'qos-drop-policy': {'v_range': [['6.4.0', '']], 'choices': ['taildrop', 'random-early-detection'], 'type': 'str'},
                'qos-red-probability': {'v_range': [['6.4.0', '']], 'type': 'int'},
                'switch-dhcp_opt43_key': {'v_range': [['6.4.0', '']], 'no_log': True, 'type': 'str'},
                'tdr-supported': {'v_range': [['6.4.3', '']], 'type': 'str'},
                'custom-command': {
                    'v_range': [['7.0.0', '']],
                    'type': 'list',
                    'options': {'command-entry': {'v_range': [['7.0.0', '']], 'type': 'str'}, 'command-name': {'v_range': [['7.0.0', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'firmware-provision': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'firmware-provision-version': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'dhcp-server-access-list': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable', 'global'], 'type': 'str'},
                'firmware-provision-latest': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'once'], 'type': 'str'},
                'dhcp-snooping-static-client': {
                    'v_range': [['7.2.2', '']],
                    'type': 'list',
                    'options': {
                        'ip': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'mac': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'name': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'port': {'v_range': [['7.2.2', '']], 'type': 'str'},
                        'vlan': {'v_range': [['7.2.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'ptp-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'ptp-status': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload-mclag': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'route-offload-router': {
                    'v_range': [['7.4.1', '']],
                    'type': 'list',
                    'options': {'router-ip': {'v_range': [['7.4.1', '']], 'type': 'str'}, 'vlan-name': {'v_range': [['7.4.1', '']], 'type': 'str'}},
                    'elements': 'dict'
                },
                'mgmt-mode': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'purdue-level': {'v_range': [['7.4.2', '']], 'choices': ['1', '2', '3', '4', '5', '1.5', '2.5', '3.5', '5.5'], 'type': 'str'},
                'radius-nas-ip': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'radius-nas-ip-override': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-discovered': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'vlan': {
                    'v_range': [['7.4.2', '']],
                    'type': 'list',
                    'options': {
                        'assignment-priority': {'v_range': [['7.4.2', '']], 'type': 'int'},
                        'vlan-name': {'v_range': [['7.4.2', '']], 'type': 'str'}
                    },
                    'elements': 'dict'
                }
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'switchcontroller_managedswitch'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    connection.set_option('access_token', module.params.get('access_token', None))
    connection.set_option('enable_log', module.params.get('enable_log', False))
    connection.set_option('forticloud_access_token', module.params.get('forticloud_access_token', None))
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
