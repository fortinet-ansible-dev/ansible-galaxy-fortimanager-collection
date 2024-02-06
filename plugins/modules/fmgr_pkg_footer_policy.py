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
module: fmgr_pkg_footer_policy
short_description: Configure IPv4/IPv6 policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_footer_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: No description.
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
                    - 'redirect'
                    - 'isolate'
            active-auth-method:
                type: str
                description: Deprecated, please rename it to active_auth_method.
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
            anti-replay:
                type: str
                description: Deprecated, please rename it to anti_replay.
                choices:
                    - 'disable'
                    - 'enable'
            app-category:
                type: raw
                description: (list or str) Deprecated, please rename it to app_category.
            app-group:
                type: raw
                description: (list or str) Deprecated, please rename it to app_group.
            application:
                type: raw
                description: (list) No description.
            application-charts:
                type: list
                elements: str
                description: Deprecated, please rename it to application_charts.
                choices:
                    - 'top10-app'
                    - 'top10-p2p-user'
                    - 'top10-media-user'
            application-list:
                type: str
                description: Deprecated, please rename it to application_list.
            auth-cert:
                type: str
                description: Deprecated, please rename it to auth_cert.
            auth-method:
                type: str
                description: Deprecated, please rename it to auth_method.
                choices:
                    - 'basic'
                    - 'digest'
                    - 'ntlm'
                    - 'fsae'
                    - 'form'
                    - 'fsso'
                    - 'rsso'
            auth-path:
                type: str
                description: Deprecated, please rename it to auth_path.
                choices:
                    - 'disable'
                    - 'enable'
            auth-portal:
                type: str
                description: Deprecated, please rename it to auth_portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth-redirect-addr:
                type: str
                description: Deprecated, please rename it to auth_redirect_addr.
            auto-asic-offload:
                type: str
                description: Deprecated, please rename it to auto_asic_offload.
                choices:
                    - 'disable'
                    - 'enable'
            av-profile:
                type: str
                description: Deprecated, please rename it to av_profile.
            bandwidth:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            block-notification:
                type: str
                description: Deprecated, please rename it to block_notification.
                choices:
                    - 'disable'
                    - 'enable'
            captive-portal-exempt:
                type: str
                description: Deprecated, please rename it to captive_portal_exempt.
                choices:
                    - 'disable'
                    - 'enable'
            capture-packet:
                type: str
                description: Deprecated, please rename it to capture_packet.
                choices:
                    - 'disable'
                    - 'enable'
            casi-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to casi_profile.
            central-nat:
                type: str
                description: Deprecated, please rename it to central_nat.
                choices:
                    - 'disable'
                    - 'enable'
            cifs-profile:
                type: str
                description: Deprecated, please rename it to cifs_profile.
            client-reputation:
                type: str
                description: Deprecated, please rename it to client_reputation.
                choices:
                    - 'disable'
                    - 'enable'
            client-reputation-mode:
                type: str
                description: Deprecated, please rename it to client_reputation_mode.
                choices:
                    - 'learning'
                    - 'monitoring'
            comments:
                type: raw
                description: (dict or str) No description.
            custom-log-fields:
                type: raw
                description: (list or str) Deprecated, please rename it to custom_log_fields.
            deep-inspection-options:
                type: raw
                description: (list or str) Deprecated, please rename it to deep_inspection_options.
            delay-tcp-npu-session:
                type: str
                description: Deprecated, please rename it to delay_tcp_npu_session.
                choices:
                    - 'disable'
                    - 'enable'
            delay-tcp-npu-sessoin:
                type: str
                description: Deprecated, please rename it to delay_tcp_npu_sessoin.
                choices:
                    - 'disable'
                    - 'enable'
            device-detection-portal:
                type: str
                description: Deprecated, please rename it to device_detection_portal.
                choices:
                    - 'disable'
                    - 'enable'
            devices:
                type: raw
                description: (list or str) No description.
            diffserv-forward:
                type: str
                description: Deprecated, please rename it to diffserv_forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-reverse:
                type: str
                description: Deprecated, please rename it to diffserv_reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode-forward:
                type: str
                description: Deprecated, please rename it to diffservcode_forward.
            diffservcode-rev:
                type: str
                description: Deprecated, please rename it to diffservcode_rev.
            disclaimer:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'user'
                    - 'domain'
                    - 'policy'
            dlp-sensor:
                type: raw
                description: (list or str) Deprecated, please rename it to dlp_sensor.
            dnsfilter-profile:
                type: str
                description: Deprecated, please rename it to dnsfilter_profile.
            dponly:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-match:
                type: str
                description: Deprecated, please rename it to dscp_match.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-negate:
                type: str
                description: Deprecated, please rename it to dscp_negate.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-value:
                type: str
                description: Deprecated, please rename it to dscp_value.
            dsri:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) No description.
            dstaddr-negate:
                type: str
                description: Deprecated, please rename it to dstaddr_negate.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: raw
                description: (list or str) No description.
            dstintf:
                type: raw
                description: (list or str) No description.
            dynamic-profile:
                type: str
                description: Deprecated, please rename it to dynamic_profile.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile-access:
                type: list
                elements: str
                description: Deprecated, please rename it to dynamic_profile_access.
                choices:
                    - 'imap'
                    - 'smtp'
                    - 'pop3'
                    - 'http'
                    - 'ftp'
                    - 'im'
                    - 'nntp'
                    - 'imaps'
                    - 'smtps'
                    - 'pop3s'
                    - 'https'
                    - 'ftps'
                    - 'ssh'
            dynamic-profile-fallthrough:
                type: str
                description: Deprecated, please rename it to dynamic_profile_fallthrough.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile-group:
                type: raw
                description: (list or str) Deprecated, please rename it to dynamic_profile_group.
            email-collect:
                type: str
                description: Deprecated, please rename it to email_collect.
                choices:
                    - 'disable'
                    - 'enable'
            email-collection-portal:
                type: str
                description: Deprecated, please rename it to email_collection_portal.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter-profile:
                type: str
                description: Deprecated, please rename it to emailfilter_profile.
            endpoint-check:
                type: str
                description: Deprecated, please rename it to endpoint_check.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-compliance:
                type: str
                description: Deprecated, please rename it to endpoint_compliance.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-keepalive-interface:
                type: raw
                description: (list or str) Deprecated, please rename it to endpoint_keepalive_interface.
            endpoint-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to endpoint_profile.
            failed-connection:
                type: str
                description: Deprecated, please rename it to failed_connection.
                choices:
                    - 'disable'
                    - 'enable'
            fall-through-unauthenticated:
                type: str
                description: Deprecated, please rename it to fall_through_unauthenticated.
                choices:
                    - 'disable'
                    - 'enable'
            firewall-session-dirty:
                type: str
                description: Deprecated, please rename it to firewall_session_dirty.
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-compliance-devices:
                type: list
                elements: str
                description: Deprecated, please rename it to forticlient_compliance_devices.
                choices:
                    - 'windows-pc'
                    - 'mac'
                    - 'iphone-ipad'
                    - 'android'
            forticlient-compliance-enforcement-portal:
                type: str
                description: Deprecated, please rename it to forticlient_compliance_enforcement_portal.
                choices:
                    - 'disable'
                    - 'enable'
            fsae:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            fsae-server-for-ntlm:
                type: raw
                description: (list or str) Deprecated, please rename it to fsae_server_for_ntlm.
            fsso:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            fsso-agent-for-ntlm:
                type: str
                description: Deprecated, please rename it to fsso_agent_for_ntlm.
            geo-location:
                type: str
                description: Deprecated, please rename it to geo_location.
                choices:
                    - 'disable'
                    - 'enable'
            geoip-anycast:
                type: str
                description: Deprecated, please rename it to geoip_anycast.
                choices:
                    - 'disable'
                    - 'enable'
            global-label:
                type: str
                description: Deprecated, please rename it to global_label.
            groups:
                type: raw
                description: (list or str) No description.
            gtp-profile:
                type: str
                description: Deprecated, please rename it to gtp_profile.
            http-policy-redirect:
                type: str
                description: Deprecated, please rename it to http_policy_redirect.
                choices:
                    - 'disable'
                    - 'enable'
            icap-profile:
                type: str
                description: Deprecated, please rename it to icap_profile.
            identity-based:
                type: str
                description: Deprecated, please rename it to identity_based.
                choices:
                    - 'disable'
                    - 'enable'
            identity-based-policy:
                type: list
                elements: dict
                description: Deprecated, please rename it to identity_based_policy.
                suboptions:
                    action:
                        type: str
                        description: No description.
                        choices:
                            - 'deny'
                            - 'accept'
                    application-charts:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to application_charts.
                        choices:
                            - 'top10-app'
                            - 'top10-p2p-user'
                            - 'top10-media-user'
                    application-list:
                        type: str
                        description: Deprecated, please rename it to application_list.
                    av-profile:
                        type: str
                        description: Deprecated, please rename it to av_profile.
                    capture-packet:
                        type: str
                        description: Deprecated, please rename it to capture_packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    deep-inspection-options:
                        type: str
                        description: Deprecated, please rename it to deep_inspection_options.
                    devices:
                        type: str
                        description: No description.
                    dlp-sensor:
                        type: str
                        description: Deprecated, please rename it to dlp_sensor.
                    dstaddr:
                        type: str
                        description: No description.
                    dstaddr-negate:
                        type: str
                        description: Deprecated, please rename it to dstaddr_negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    endpoint-compliance:
                        type: str
                        description: Deprecated, please rename it to endpoint_compliance.
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: No description.
                    icap-profile:
                        type: str
                        description: Deprecated, please rename it to icap_profile.
                    id:
                        type: int
                        description: No description.
                    ips-sensor:
                        type: str
                        description: Deprecated, please rename it to ips_sensor.
                    logtraffic:
                        type: str
                        description: No description.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'all'
                            - 'utm'
                    logtraffic-app:
                        type: str
                        description: Deprecated, please rename it to logtraffic_app.
                        choices:
                            - 'disable'
                            - 'enable'
                    logtraffic-start:
                        type: str
                        description: Deprecated, please rename it to logtraffic_start.
                        choices:
                            - 'disable'
                            - 'enable'
                    mms-profile:
                        type: str
                        description: Deprecated, please rename it to mms_profile.
                    per-ip-shaper:
                        type: str
                        description: Deprecated, please rename it to per_ip_shaper.
                    profile-group:
                        type: str
                        description: Deprecated, please rename it to profile_group.
                    profile-protocol-options:
                        type: str
                        description: Deprecated, please rename it to profile_protocol_options.
                    profile-type:
                        type: str
                        description: Deprecated, please rename it to profile_type.
                        choices:
                            - 'single'
                            - 'group'
                    replacemsg-group:
                        type: str
                        description: Deprecated, please rename it to replacemsg_group.
                    schedule:
                        type: str
                        description: No description.
                    send-deny-packet:
                        type: str
                        description: Deprecated, please rename it to send_deny_packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    service:
                        type: str
                        description: No description.
                    service-negate:
                        type: str
                        description: Deprecated, please rename it to service_negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    spamfilter-profile:
                        type: str
                        description: Deprecated, please rename it to spamfilter_profile.
                    sslvpn-portal:
                        type: str
                        description: Deprecated, please rename it to sslvpn_portal.
                    sslvpn-realm:
                        type: str
                        description: Deprecated, please rename it to sslvpn_realm.
                    traffic-shaper:
                        type: str
                        description: Deprecated, please rename it to traffic_shaper.
                    traffic-shaper-reverse:
                        type: str
                        description: Deprecated, please rename it to traffic_shaper_reverse.
                    users:
                        type: str
                        description: No description.
                    utm-status:
                        type: str
                        description: Deprecated, please rename it to utm_status.
                        choices:
                            - 'disable'
                            - 'enable'
                    voip-profile:
                        type: str
                        description: Deprecated, please rename it to voip_profile.
                    webfilter-profile:
                        type: str
                        description: Deprecated, please rename it to webfilter_profile.
            identity-based-route:
                type: str
                description: Deprecated, please rename it to identity_based_route.
            identity-from:
                type: str
                description: Deprecated, please rename it to identity_from.
                choices:
                    - 'auth'
                    - 'device'
            inbound:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            inspection-mode:
                type: str
                description: Deprecated, please rename it to inspection_mode.
                choices:
                    - 'proxy'
                    - 'flow'
            internet-service:
                type: str
                description: Deprecated, please rename it to internet_service.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom.
            internet-service-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom_group.
            internet-service-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_group.
            internet-service-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_id.
            internet-service-negate:
                type: str
                description: Deprecated, please rename it to internet_service_negate.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: Deprecated, please rename it to internet_service_src.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom.
            internet-service-src-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom_group.
            internet-service-src-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_group.
            internet-service-src-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_id.
            internet-service-src-negate:
                type: str
                description: Deprecated, please rename it to internet_service_src_negate.
                choices:
                    - 'disable'
                    - 'enable'
            ip-based:
                type: str
                description: Deprecated, please rename it to ip_based.
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor.
            label:
                type: str
                description: No description.
            learning-mode:
                type: str
                description: Deprecated, please rename it to learning_mode.
                choices:
                    - 'disable'
                    - 'enable'
            log-unmatched-traffic:
                type: str
                description: Deprecated, please rename it to log_unmatched_traffic.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic-app:
                type: str
                description: Deprecated, please rename it to logtraffic_app.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic-start:
                type: str
                description: Deprecated, please rename it to logtraffic_start.
                choices:
                    - 'disable'
                    - 'enable'
            match-vip:
                type: str
                description: Deprecated, please rename it to match_vip.
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to mms_profile.
            name:
                type: str
                description: No description.
            nat:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            natip:
                type: str
                description: No description.
            natoutbound:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            np-acceleration:
                type: str
                description: Deprecated, please rename it to np_acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm-enabled-browsers:
                type: raw
                description: (list) Deprecated, please rename it to ntlm_enabled_browsers.
            ntlm-guest:
                type: str
                description: Deprecated, please rename it to ntlm_guest.
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: Deprecated, please rename it to per_ip_shaper.
            permit-any-host:
                type: str
                description: Deprecated, please rename it to permit_any_host.
                choices:
                    - 'disable'
                    - 'enable'
            permit-stun-host:
                type: str
                description: Deprecated, please rename it to permit_stun_host.
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: No description.
                required: true
            poolname:
                type: raw
                description: (list or str) No description.
            profile-group:
                type: str
                description: Deprecated, please rename it to profile_group.
            profile-protocol-options:
                type: str
                description: Deprecated, please rename it to profile_protocol_options.
            profile-type:
                type: str
                description: Deprecated, please rename it to profile_type.
                choices:
                    - 'single'
                    - 'group'
            radius-mac-auth-bypass:
                type: str
                description: Deprecated, please rename it to radius_mac_auth_bypass.
                choices:
                    - 'disable'
                    - 'enable'
            redirect-url:
                type: str
                description: Deprecated, please rename it to redirect_url.
            replacemsg-group:
                type: raw
                description: (list or str) Deprecated, please rename it to replacemsg_group.
            replacemsg-override-group:
                type: str
                description: Deprecated, please rename it to replacemsg_override_group.
            reputation-direction:
                type: str
                description: Deprecated, please rename it to reputation_direction.
                choices:
                    - 'source'
                    - 'destination'
            reputation-minimum:
                type: int
                description: Deprecated, please rename it to reputation_minimum.
            require-tfa:
                type: str
                description: Deprecated, please rename it to require_tfa.
                choices:
                    - 'disable'
                    - 'enable'
            rsso:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            rtp-addr:
                type: raw
                description: (list or str) Deprecated, please rename it to rtp_addr.
            rtp-nat:
                type: str
                description: Deprecated, please rename it to rtp_nat.
                choices:
                    - 'disable'
                    - 'enable'
            scan-botnet-connections:
                type: str
                description: Deprecated, please rename it to scan_botnet_connections.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: No description.
            schedule-timeout:
                type: str
                description: Deprecated, please rename it to schedule_timeout.
                choices:
                    - 'disable'
                    - 'enable'
            send-deny-packet:
                type: str
                description: Deprecated, please rename it to send_deny_packet.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: raw
                description: (list or str) No description.
            service-negate:
                type: str
                description: Deprecated, please rename it to service_negate.
                choices:
                    - 'disable'
                    - 'enable'
            session-ttl:
                type: raw
                description: (int or str) Deprecated, please rename it to session_ttl.
            sessions:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to spamfilter_profile.
            srcaddr:
                type: raw
                description: (list or str) No description.
            srcaddr-negate:
                type: str
                description: Deprecated, please rename it to srcaddr_negate.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: raw
                description: (list or str) No description.
            srcintf:
                type: raw
                description: (list or str) No description.
            ssh-filter-profile:
                type: str
                description: Deprecated, please rename it to ssh_filter_profile.
            ssh-policy-redirect:
                type: str
                description: Deprecated, please rename it to ssh_policy_redirect.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror:
                type: str
                description: Deprecated, please rename it to ssl_mirror.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror-intf:
                type: raw
                description: (list or str) Deprecated, please rename it to ssl_mirror_intf.
            ssl-ssh-profile:
                type: str
                description: Deprecated, please rename it to ssl_ssh_profile.
            sslvpn-auth:
                type: str
                description: Deprecated, please rename it to sslvpn_auth.
                choices:
                    - 'any'
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs+'
            sslvpn-ccert:
                type: str
                description: Deprecated, please rename it to sslvpn_ccert.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-cipher:
                type: str
                description: Deprecated, please rename it to sslvpn_cipher.
                choices:
                    - 'any'
                    - 'high'
                    - 'medium'
            sso-auth-method:
                type: str
                description: Deprecated, please rename it to sso_auth_method.
                choices:
                    - 'fsso'
                    - 'rsso'
            status:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: raw
                description: (list or str) No description.
            tcp-mss-receiver:
                type: int
                description: Deprecated, please rename it to tcp_mss_receiver.
            tcp-mss-sender:
                type: int
                description: Deprecated, please rename it to tcp_mss_sender.
            tcp-reset:
                type: str
                description: Deprecated, please rename it to tcp_reset.
                choices:
                    - 'disable'
                    - 'enable'
            tcp-session-without-syn:
                type: str
                description: Deprecated, please rename it to tcp_session_without_syn.
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout-send-rst:
                type: str
                description: Deprecated, please rename it to timeout_send_rst.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: No description.
            tos-mask:
                type: str
                description: Deprecated, please rename it to tos_mask.
            tos-negate:
                type: str
                description: Deprecated, please rename it to tos_negate.
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper.
            traffic-shaper-reverse:
                type: str
                description: Deprecated, please rename it to traffic_shaper_reverse.
            transaction-based:
                type: str
                description: Deprecated, please rename it to transaction_based.
                choices:
                    - 'disable'
                    - 'enable'
            url-category:
                type: raw
                description: (list or str) Deprecated, please rename it to url_category.
            users:
                type: raw
                description: (list or str) No description.
            utm-inspection-mode:
                type: str
                description: Deprecated, please rename it to utm_inspection_mode.
                choices:
                    - 'proxy'
                    - 'flow'
            utm-status:
                type: str
                description: Deprecated, please rename it to utm_status.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: No description.
            vlan-cos-fwd:
                type: int
                description: Deprecated, please rename it to vlan_cos_fwd.
            vlan-cos-rev:
                type: int
                description: Deprecated, please rename it to vlan_cos_rev.
            vlan-filter:
                type: str
                description: Deprecated, please rename it to vlan_filter.
            voip-profile:
                type: str
                description: Deprecated, please rename it to voip_profile.
            vpntunnel:
                type: str
                description: No description.
            waf-profile:
                type: str
                description: Deprecated, please rename it to waf_profile.
            wanopt:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            wanopt-detection:
                type: str
                description: Deprecated, please rename it to wanopt_detection.
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt-passive-opt:
                type: str
                description: Deprecated, please rename it to wanopt_passive_opt.
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt-peer:
                type: str
                description: Deprecated, please rename it to wanopt_peer.
            wanopt-profile:
                type: str
                description: Deprecated, please rename it to wanopt_profile.
            wccp:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            web-auth-cookie:
                type: str
                description: Deprecated, please rename it to web_auth_cookie.
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            webcache-https:
                type: str
                description: Deprecated, please rename it to webcache_https.
                choices:
                    - 'disable'
                    - 'ssl-server'
                    - 'any'
                    - 'enable'
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile.
            webproxy-forward-server:
                type: str
                description: Deprecated, please rename it to webproxy_forward_server.
            webproxy-profile:
                type: str
                description: Deprecated, please rename it to webproxy_profile.
            wsso:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            fsso-groups:
                type: raw
                description: (list or str) Deprecated, please rename it to fsso_groups.
            match-vip-only:
                type: str
                description: Deprecated, please rename it to match_vip_only.
                choices:
                    - 'disable'
                    - 'enable'
            np-accelation:
                type: str
                description: Deprecated, please rename it to np_accelation.
                choices:
                    - 'disable'
                    - 'enable'
            best-route:
                type: str
                description: Deprecated, please rename it to best_route.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted-traffic-mirror:
                type: str
                description: Deprecated, please rename it to decrypted_traffic_mirror.
            geoip-match:
                type: str
                description: Deprecated, please rename it to geoip_match.
                choices:
                    - 'physical-location'
                    - 'registered-location'
            internet-service-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_name.
            internet-service-src-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_name.
            poolname6:
                type: raw
                description: (list or str) No description.
            src-vendor-mac:
                type: raw
                description: (list or str) Deprecated, please rename it to src_vendor_mac.
            vendor-mac:
                type: raw
                description: (list or str) Deprecated, please rename it to vendor_mac.
            file-filter-profile:
                type: str
                description: Deprecated, please rename it to file_filter_profile.
            cgn-eif:
                type: str
                description: Deprecated, please rename it to cgn_eif. Enable/Disable CGN endpoint independent filtering.
                choices:
                    - 'disable'
                    - 'enable'
            cgn-eim:
                type: str
                description: Deprecated, please rename it to cgn_eim. Enable/Disable CGN endpoint independent mapping
                choices:
                    - 'disable'
                    - 'enable'
            cgn-log-server-grp:
                type: raw
                description: (list or str) Deprecated, please rename it to cgn_log_server_grp. NP log server group name
            cgn-resource-quota:
                type: int
                description: Deprecated, please rename it to cgn_resource_quota. Resource quota
            cgn-session-quota:
                type: int
                description: Deprecated, please rename it to cgn_session_quota. Session quota
            policy-offload:
                type: str
                description: Deprecated, please rename it to policy_offload. Enable/Disable hardware session setup for CGNAT.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-shaping:
                type: str
                description: Deprecated, please rename it to dynamic_shaping. Enable/disable dynamic RADIUS defined traffic shaping.
                choices:
                    - 'disable'
                    - 'enable'
            passive-wan-health-measurement:
                type: str
                description: Deprecated, please rename it to passive_wan_health_measurement. Enable/disable passive WAN health measurement.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter-profile:
                type: str
                description: Deprecated, please rename it to videofilter_profile. Name of an existing VideoFilter profile.
            ztna-ems-tag:
                type: raw
                description: (list or str) Deprecated, please rename it to ztna_ems_tag. Source ztna-ems-tag names.
            ztna-geo-tag:
                type: raw
                description: (list or str) Deprecated, please rename it to ztna_geo_tag. Source ztna-geo-tag names.
            ztna-status:
                type: str
                description: Deprecated, please rename it to ztna_status. Enable/disable zero trust access.
                choices:
                    - 'disable'
                    - 'enable'
            access-proxy:
                type: raw
                description: (list) Deprecated, please rename it to access_proxy.
            dlp-profile:
                type: str
                description: Deprecated, please rename it to dlp_profile. Name of an existing DLP profile.
            dynamic-bypass:
                type: str
                description: Deprecated, please rename it to dynamic_bypass.
                choices:
                    - 'disable'
                    - 'enable'
            fec:
                type: str
                description: Enable/disable Forward Error Correction on traffic matching this policy on a FEC device.
                choices:
                    - 'disable'
                    - 'enable'
            force-proxy:
                type: str
                description: Deprecated, please rename it to force_proxy.
                choices:
                    - 'disable'
                    - 'enable'
            http-tunnel-auth:
                type: str
                description: Deprecated, please rename it to http_tunnel_auth.
                choices:
                    - 'disable'
                    - 'enable'
            ia-profile:
                type: raw
                description: (list) Deprecated, please rename it to ia_profile.
            isolator-server:
                type: raw
                description: (list) Deprecated, please rename it to isolator_server.
            log-http-transaction:
                type: str
                description: Deprecated, please rename it to log_http_transaction.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            max-session-per-user:
                type: int
                description: Deprecated, please rename it to max_session_per_user.
            nat46:
                type: str
                description: Enable/disable NAT46.
                choices:
                    - 'disable'
                    - 'enable'
            nat64:
                type: str
                description: Enable/disable NAT64.
                choices:
                    - 'disable'
                    - 'enable'
            pass-through:
                type: str
                description: Deprecated, please rename it to pass_through.
                choices:
                    - 'disable'
                    - 'enable'
            pfcp-profile:
                type: str
                description: Deprecated, please rename it to pfcp_profile. PFCP profile.
            policy-expiry:
                type: str
                description: Deprecated, please rename it to policy_expiry. Enable/disable policy expiry.
                choices:
                    - 'disable'
                    - 'enable'
            policy-expiry-date:
                type: str
                description: Deprecated, please rename it to policy_expiry_date. Policy expiry date
            reverse-cache:
                type: str
                description: Deprecated, please rename it to reverse_cache.
                choices:
                    - 'disable'
                    - 'enable'
            sctp-filter-profile:
                type: str
                description: Deprecated, please rename it to sctp_filter_profile. Name of an existing SCTP filter profile.
            sgt:
                type: raw
                description: (list) No description.
            sgt-check:
                type: str
                description: Deprecated, please rename it to sgt_check. Enable/disable security group tags
                choices:
                    - 'disable'
                    - 'enable'
            tcp-timeout-pid:
                type: raw
                description: (list) Deprecated, please rename it to tcp_timeout_pid.
            transparent:
                type: str
                description: No description.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: No description.
                choices:
                    - 'explicit-web'
                    - 'transparent'
                    - 'explicit-ftp'
                    - 'ssh-tunnel'
                    - 'ssh'
                    - 'wanopt'
                    - 'access-proxy'
            udp-timeout-pid:
                type: raw
                description: (list) Deprecated, please rename it to udp_timeout_pid.
            ztna-tags-match-logic:
                type: str
                description: Deprecated, please rename it to ztna_tags_match_logic.
                choices:
                    - 'or'
                    - 'and'
            uuid-idx:
                type: int
                description: Deprecated, please rename it to uuid_idx.
            device-ownership:
                type: str
                description: Deprecated, please rename it to device_ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ssh-policy-check:
                type: str
                description: Deprecated, please rename it to ssh_policy_check.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-copy:
                type: str
                description: Deprecated, please rename it to diffserv_copy. Enable to copy packets DiffServ values from sessions original direction to ...
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6-negate:
                type: str
                description: Deprecated, please rename it to dstaddr6_negate. When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6:
                type: str
                description: Deprecated, please rename it to internet_service6. Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-custom:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_custom.
            internet-service6-custom-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_custom_group.
            internet-service6-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_group.
            internet-service6-name:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_name.
            internet-service6-negate:
                type: str
                description: Deprecated, please rename it to internet_service6_negate. When enabled internet-service6 specifies what the service must N...
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-src:
                type: str
                description: Deprecated, please rename it to internet_service6_src. Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service6-src-custom:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_custom.
            internet-service6-src-custom-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_custom_group.
            internet-service6-src-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_group.
            internet-service6-src-name:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_name.
            internet-service6-src-negate:
                type: str
                description: Deprecated, please rename it to internet_service6_src_negate. When enabled internet-service6-src specifies what the servic...
                choices:
                    - 'disable'
                    - 'enable'
            network-service-dynamic:
                type: raw
                description: (list) Deprecated, please rename it to network_service_dynamic.
            network-service-src-dynamic:
                type: raw
                description: (list) Deprecated, please rename it to network_service_src_dynamic.
            reputation-direction6:
                type: str
                description: Deprecated, please rename it to reputation_direction6. Direction of the initial traffic for IPv6 reputation to take effect.
                choices:
                    - 'source'
                    - 'destination'
            reputation-minimum6:
                type: int
                description: Deprecated, please rename it to reputation_minimum6. IPv6 Minimum Reputation to take action.
            srcaddr6-negate:
                type: str
                description: Deprecated, please rename it to srcaddr6_negate. When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            _policy_block:
                type: int
                description: Assigned policy block.
            isolator-profile:
                type: raw
                description: (list) Deprecated, please rename it to isolator_profile.
            policy-expiry-date-utc:
                type: str
                description: Deprecated, please rename it to policy_expiry_date_utc. Policy expiry date and time, in epoch format.
            ztna-device-ownership:
                type: str
                description: Deprecated, please rename it to ztna_device_ownership. Enable/disable zero trust device ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ztna-policy-redirect:
                type: str
                description: Deprecated, please rename it to ztna_policy_redirect. Redirect ZTNA traffic to matching Access-Proxy proxy-policy.
                choices:
                    - 'disable'
                    - 'enable'
            ip-version-type:
                type: str
                description: Deprecated, please rename it to ip_version_type. IP version of the policy.
            ips-voip-filter:
                type: str
                description: Deprecated, please rename it to ips_voip_filter. Name of an existing VoIP
            policy-behaviour-type:
                type: str
                description: Deprecated, please rename it to policy_behaviour_type. Behaviour of the policy.
            pcp-inbound:
                type: str
                description: Deprecated, please rename it to pcp_inbound. Enable/disable PCP inbound DNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp-outbound:
                type: str
                description: Deprecated, please rename it to pcp_outbound. Enable/disable PCP outbound SNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp-poolname:
                type: raw
                description: (list) Deprecated, please rename it to pcp_poolname.
            ztna-ems-tag-secondary:
                type: raw
                description: (list) Deprecated, please rename it to ztna_ems_tag_secondary.
            casb-profile:
                type: str
                description: Deprecated, please rename it to casb_profile. Name of an existing CASB profile.
            extended-log:
                type: str
                description: Deprecated, please rename it to extended_log.
                choices:
                    - 'disable'
                    - 'enable'
            implicit-proxy-detection:
                type: str
                description: Deprecated, please rename it to implicit_proxy_detection.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-patch-profile:
                type: str
                description: Deprecated, please rename it to virtual_patch_profile. Name of an existing virtual-patch profile.
            detect-https-in-http-request:
                type: str
                description: Deprecated, please rename it to detect_https_in_http_request.
                choices:
                    - 'disable'
                    - 'enable'
            diameter-filter-profile:
                type: str
                description: Deprecated, please rename it to diameter_filter_profile. Name of an existing Diameter filter profile.
            redirect-profile:
                type: raw
                description: (list) Deprecated, please rename it to redirect_profile.
'''

EXAMPLES = '''
- name: Example playbook
  hosts: fortimanagers
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Configure IPv4 footer policies.
      fortinet.fortimanager.fmgr_pkg_footer_policy:
        bypass_validation: false
        pkg: ansible
        state: present
        pkg_footer_policy:
          action: accept # <value in [deny, accept, ipsec, ...]>
          dstaddr: gall
          dstintf: any
          name: ansible-test-footer
          policyid: 1074741836 # must larger than 2^30(1074741824), since header/footer policy is a special policy
          schedule: galways
          service: gALL
          srcaddr: gall
          srcintf: any
          status: enable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 footer policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_footer_policy"
          params:
            pkg: "ansible"
            policy: "your_value"
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
        '/pm/config/global/pkg/{pkg}/global/footer/policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/footer/policy/{policy}'
    ]

    url_params = ['pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'pkg': {'required': True, 'type': 'str'},
        'pkg_footer_policy': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'action': {'choices': ['deny', 'accept', 'ipsec', 'ssl-vpn', 'redirect', 'isolate'], 'type': 'str'},
                'active-auth-method': {'choices': ['ntlm', 'basic', 'digest', 'form'], 'type': 'str'},
                'anti-replay': {'choices': ['disable', 'enable'], 'type': 'str'},
                'app-category': {'type': 'raw'},
                'app-group': {'type': 'raw'},
                'application': {'type': 'raw'},
                'application-charts': {'type': 'list', 'choices': ['top10-app', 'top10-p2p-user', 'top10-media-user'], 'elements': 'str'},
                'application-list': {'type': 'str'},
                'auth-cert': {'type': 'str'},
                'auth-method': {'choices': ['basic', 'digest', 'ntlm', 'fsae', 'form', 'fsso', 'rsso'], 'type': 'str'},
                'auth-path': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-portal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'auth-redirect-addr': {'type': 'str'},
                'auto-asic-offload': {'choices': ['disable', 'enable'], 'type': 'str'},
                'av-profile': {'type': 'str'},
                'bandwidth': {'choices': ['disable', 'enable'], 'type': 'str'},
                'block-notification': {'choices': ['disable', 'enable'], 'type': 'str'},
                'captive-portal-exempt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'capture-packet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'casi-profile': {'type': 'raw'},
                'central-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'cifs-profile': {'type': 'str'},
                'client-reputation': {'choices': ['disable', 'enable'], 'type': 'str'},
                'client-reputation-mode': {'choices': ['learning', 'monitoring'], 'type': 'str'},
                'comments': {'type': 'raw'},
                'custom-log-fields': {'type': 'raw'},
                'deep-inspection-options': {'type': 'raw'},
                'delay-tcp-npu-session': {'choices': ['disable', 'enable'], 'type': 'str'},
                'delay-tcp-npu-sessoin': {'choices': ['disable', 'enable'], 'type': 'str'},
                'device-detection-portal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'devices': {'type': 'raw'},
                'diffserv-forward': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-reverse': {'choices': ['disable', 'enable'], 'type': 'str'},
                'diffservcode-forward': {'type': 'str'},
                'diffservcode-rev': {'type': 'str'},
                'disclaimer': {'choices': ['disable', 'enable', 'user', 'domain', 'policy'], 'type': 'str'},
                'dlp-sensor': {'type': 'raw'},
                'dnsfilter-profile': {'type': 'str'},
                'dponly': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-match': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dscp-value': {'type': 'str'},
                'dsri': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'type': 'raw'},
                'dstaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6': {'type': 'raw'},
                'dstintf': {'type': 'raw'},
                'dynamic-profile': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic-profile-access': {
                    'type': 'list',
                    'choices': ['imap', 'smtp', 'pop3', 'http', 'ftp', 'im', 'nntp', 'imaps', 'smtps', 'pop3s', 'https', 'ftps', 'ssh'],
                    'elements': 'str'
                },
                'dynamic-profile-fallthrough': {'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic-profile-group': {'type': 'raw'},
                'email-collect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'email-collection-portal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'emailfilter-profile': {'type': 'str'},
                'endpoint-check': {'choices': ['disable', 'enable'], 'type': 'str'},
                'endpoint-compliance': {'choices': ['disable', 'enable'], 'type': 'str'},
                'endpoint-keepalive-interface': {'type': 'raw'},
                'endpoint-profile': {'type': 'raw'},
                'failed-connection': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fall-through-unauthenticated': {'choices': ['disable', 'enable'], 'type': 'str'},
                'firewall-session-dirty': {'choices': ['check-all', 'check-new'], 'type': 'str'},
                'fixedport': {'choices': ['disable', 'enable'], 'type': 'str'},
                'forticlient-compliance-devices': {'type': 'list', 'choices': ['windows-pc', 'mac', 'iphone-ipad', 'android'], 'elements': 'str'},
                'forticlient-compliance-enforcement-portal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fsae': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fsae-server-for-ntlm': {'type': 'raw'},
                'fsso': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fsso-agent-for-ntlm': {'type': 'str'},
                'geo-location': {'choices': ['disable', 'enable'], 'type': 'str'},
                'geoip-anycast': {'choices': ['disable', 'enable'], 'type': 'str'},
                'global-label': {'type': 'str'},
                'groups': {'type': 'raw'},
                'gtp-profile': {'type': 'str'},
                'http-policy-redirect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'icap-profile': {'type': 'str'},
                'identity-based': {'choices': ['disable', 'enable'], 'type': 'str'},
                'identity-based-policy': {
                    'v_range': [['6.0.0', '6.2.0']],
                    'type': 'list',
                    'options': {
                        'action': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['deny', 'accept'], 'type': 'str'},
                        'application-charts': {
                            'v_range': [['6.0.0', '6.2.0']],
                            'type': 'list',
                            'choices': ['top10-app', 'top10-p2p-user', 'top10-media-user'],
                            'elements': 'str'
                        },
                        'application-list': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'av-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'capture-packet': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'deep-inspection-options': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'devices': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'dlp-sensor': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'dstaddr': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'dstaddr-negate': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'endpoint-compliance': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'groups': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'icap-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'id': {'v_range': [['6.0.0', '6.2.0']], 'type': 'int'},
                        'ips-sensor': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'logtraffic': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                        'logtraffic-app': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'logtraffic-start': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'mms-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'per-ip-shaper': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'profile-group': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'profile-protocol-options': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'profile-type': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['single', 'group'], 'type': 'str'},
                        'replacemsg-group': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'schedule': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'send-deny-packet': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'service': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'service-negate': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'spamfilter-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'sslvpn-portal': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'sslvpn-realm': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'traffic-shaper': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'traffic-shaper-reverse': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'users': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'utm-status': {'v_range': [['6.0.0', '6.2.0']], 'choices': ['disable', 'enable'], 'type': 'str'},
                        'voip-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'},
                        'webfilter-profile': {'v_range': [['6.0.0', '6.2.0']], 'type': 'str'}
                    },
                    'elements': 'dict'
                },
                'identity-based-route': {'type': 'str'},
                'identity-from': {'choices': ['auth', 'device'], 'type': 'str'},
                'inbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'inspection-mode': {'choices': ['proxy', 'flow'], 'type': 'str'},
                'internet-service': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'type': 'raw'},
                'internet-service-custom-group': {'type': 'raw'},
                'internet-service-group': {'type': 'raw'},
                'internet-service-id': {'type': 'raw'},
                'internet-service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'type': 'raw'},
                'internet-service-src-custom-group': {'type': 'raw'},
                'internet-service-src-group': {'type': 'raw'},
                'internet-service-src-id': {'type': 'raw'},
                'internet-service-src-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-based': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ippool': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'type': 'str'},
                'label': {'type': 'str'},
                'learning-mode': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-unmatched-traffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic': {'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-app': {'choices': ['disable', 'enable'], 'type': 'str'},
                'logtraffic-start': {'choices': ['disable', 'enable'], 'type': 'str'},
                'match-vip': {'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'type': 'raw'},
                'name': {'type': 'str'},
                'nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'natinbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'natip': {'type': 'str'},
                'natoutbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'np-acceleration': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ntlm': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ntlm-enabled-browsers': {'type': 'raw'},
                'ntlm-guest': {'choices': ['disable', 'enable'], 'type': 'str'},
                'outbound': {'choices': ['disable', 'enable'], 'type': 'str'},
                'per-ip-shaper': {'type': 'str'},
                'permit-any-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'permit-stun-host': {'choices': ['disable', 'enable'], 'type': 'str'},
                'policyid': {'required': True, 'type': 'int'},
                'poolname': {'type': 'raw'},
                'profile-group': {'type': 'str'},
                'profile-protocol-options': {'type': 'str'},
                'profile-type': {'choices': ['single', 'group'], 'type': 'str'},
                'radius-mac-auth-bypass': {'choices': ['disable', 'enable'], 'type': 'str'},
                'redirect-url': {'type': 'str'},
                'replacemsg-group': {'type': 'raw'},
                'replacemsg-override-group': {'type': 'str'},
                'reputation-direction': {'choices': ['source', 'destination'], 'type': 'str'},
                'reputation-minimum': {'type': 'int'},
                'require-tfa': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rsso': {'choices': ['disable', 'enable'], 'type': 'str'},
                'rtp-addr': {'type': 'raw'},
                'rtp-nat': {'choices': ['disable', 'enable'], 'type': 'str'},
                'scan-botnet-connections': {'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'schedule': {'type': 'str'},
                'schedule-timeout': {'choices': ['disable', 'enable'], 'type': 'str'},
                'send-deny-packet': {'choices': ['disable', 'enable'], 'type': 'str'},
                'service': {'type': 'raw'},
                'service-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'session-ttl': {'type': 'raw'},
                'sessions': {'choices': ['disable', 'enable'], 'type': 'str'},
                'spamfilter-profile': {'type': 'raw'},
                'srcaddr': {'type': 'raw'},
                'srcaddr-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr6': {'type': 'raw'},
                'srcintf': {'type': 'raw'},
                'ssh-filter-profile': {'type': 'str'},
                'ssh-policy-redirect': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-mirror': {'choices': ['disable', 'enable'], 'type': 'str'},
                'ssl-mirror-intf': {'type': 'raw'},
                'ssl-ssh-profile': {'type': 'str'},
                'sslvpn-auth': {'choices': ['any', 'local', 'radius', 'ldap', 'tacacs+'], 'type': 'str'},
                'sslvpn-ccert': {'choices': ['disable', 'enable'], 'type': 'str'},
                'sslvpn-cipher': {'choices': ['any', 'high', 'medium'], 'type': 'str'},
                'sso-auth-method': {'choices': ['fsso', 'rsso'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tags': {'type': 'raw'},
                'tcp-mss-receiver': {'type': 'int'},
                'tcp-mss-sender': {'type': 'int'},
                'tcp-reset': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-session-without-syn': {'choices': ['all', 'data-only', 'disable'], 'type': 'str'},
                'timeout-send-rst': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tos': {'type': 'str'},
                'tos-mask': {'type': 'str'},
                'tos-negate': {'choices': ['disable', 'enable'], 'type': 'str'},
                'traffic-shaper': {'type': 'str'},
                'traffic-shaper-reverse': {'type': 'str'},
                'transaction-based': {'choices': ['disable', 'enable'], 'type': 'str'},
                'url-category': {'type': 'raw'},
                'users': {'type': 'raw'},
                'utm-inspection-mode': {'choices': ['proxy', 'flow'], 'type': 'str'},
                'utm-status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'type': 'str'},
                'vlan-cos-fwd': {'type': 'int'},
                'vlan-cos-rev': {'type': 'int'},
                'vlan-filter': {'type': 'str'},
                'voip-profile': {'type': 'str'},
                'vpntunnel': {'type': 'str'},
                'waf-profile': {'type': 'str'},
                'wanopt': {'choices': ['disable', 'enable'], 'type': 'str'},
                'wanopt-detection': {'choices': ['active', 'passive', 'off'], 'type': 'str'},
                'wanopt-passive-opt': {'choices': ['default', 'transparent', 'non-transparent'], 'type': 'str'},
                'wanopt-peer': {'type': 'str'},
                'wanopt-profile': {'type': 'str'},
                'wccp': {'choices': ['disable', 'enable'], 'type': 'str'},
                'web-auth-cookie': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webcache-https': {'choices': ['disable', 'ssl-server', 'any', 'enable'], 'type': 'str'},
                'webfilter-profile': {'type': 'str'},
                'webproxy-forward-server': {'type': 'str'},
                'webproxy-profile': {'type': 'str'},
                'wsso': {'choices': ['disable', 'enable'], 'type': 'str'},
                'fsso-groups': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'match-vip-only': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'np-accelation': {'v_range': [['6.2.1', '6.4.13']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'best-route': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'geoip-match': {'v_range': [['6.4.0', '']], 'choices': ['physical-location', 'registered-location'], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'poolname6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'src-vendor-mac': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'vendor-mac': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'file-filter-profile': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'cgn-eif': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-eim': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'raw'},
                'cgn-resource-quota': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'cgn-session-quota': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'type': 'int'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.12'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dynamic-shaping': {'v_range': [['6.4.6', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'passive-wan-health-measurement': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'videofilter-profile': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'ztna-ems-tag': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'ztna-geo-tag': {'v_range': [['7.0.0', '']], 'type': 'raw'},
                'ztna-status': {'v_range': [['7.0.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'access-proxy': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'dlp-profile': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'dynamic-bypass': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'fec': {'v_range': [['7.0.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'force-proxy': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'http-tunnel-auth': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ia-profile': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'isolator-server': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'log-http-transaction': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable', 'all', 'utm'], 'type': 'str'},
                'max-session-per-user': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'nat46': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pass-through': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pfcp-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'policy-expiry': {'v_range': [['7.2.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'policy-expiry-date': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'reverse-cache': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sctp-filter-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'sgt': {'v_range': [['7.0.1', '']], 'type': 'raw'},
                'sgt-check': {'v_range': [['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'tcp-timeout-pid': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'transparent': {'v_range': [['7.0.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'type': {
                    'v_range': [['7.0.3', '']],
                    'choices': ['explicit-web', 'transparent', 'explicit-ftp', 'ssh-tunnel', 'ssh', 'wanopt', 'access-proxy'],
                    'type': 'str'
                },
                'udp-timeout-pid': {'v_range': [['7.0.3', '']], 'type': 'raw'},
                'ztna-tags-match-logic': {'v_range': [['7.0.3', '']], 'choices': ['or', 'and'], 'type': 'str'},
                'uuid-idx': {'v_range': [['7.0.1', '']], 'type': 'int'},
                'device-ownership': {'v_range': [['7.0.5', '7.0.10'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-policy-check': {'v_range': [['7.0.5', '7.0.10'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diffserv-copy': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-custom': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-custom-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-name': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-src-custom': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-custom-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-group': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-name': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'internet-service6-src-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'network-service-dynamic': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'network-service-src-dynamic': {'v_range': [['7.2.1', '']], 'type': 'raw'},
                'reputation-direction6': {'v_range': [['7.2.1', '']], 'choices': ['source', 'destination'], 'type': 'str'},
                'reputation-minimum6': {'v_range': [['7.2.1', '']], 'type': 'int'},
                'srcaddr6-negate': {'v_range': [['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                '_policy_block': {'v_range': [['7.2.2', '']], 'type': 'int'},
                'isolator-profile': {'v_range': [['7.2.2', '']], 'type': 'raw'},
                'policy-expiry-date-utc': {'v_range': [['7.2.2', '']], 'type': 'str'},
                'ztna-device-ownership': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ztna-policy-redirect': {'v_range': [['7.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ip-version-type': {'v_range': [['7.2.3', '']], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.2.3', '']], 'type': 'str'},
                'policy-behaviour-type': {'v_range': [['7.2.3', '']], 'type': 'str'},
                'pcp-inbound': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pcp-outbound': {'v_range': [['7.4.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'pcp-poolname': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                'ztna-ems-tag-secondary': {'v_range': [['7.4.0', '']], 'type': 'raw'},
                'casb-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'extended-log': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'implicit-proxy-detection': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'detect-https-in-http-request': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'redirect-profile': {'v_range': [['7.4.2', '']], 'type': 'raw'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = [
        {
            'attribute_path': ['pkg_footer_policy', 'policyid'],
            'lambda': 'int($) >= 1073741824',
            'fail_action': 'warn',
            'hint_message': 'policyid should be larger than 2^30, i.e. 1073741824, otherwise it will be ignored.'
        }
    ]

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_footer_policy'),
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
