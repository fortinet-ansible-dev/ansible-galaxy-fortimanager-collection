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
module: fmgr_pkg_header_policy
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
    pkg_header_policy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Action.
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
                    - 'redirect'
                    - 'isolate'
            active-auth-method:
                type: str
                description: Deprecated, please rename it to active_auth_method. Active auth method.
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
            anti-replay:
                type: str
                description: Deprecated, please rename it to anti_replay. Anti replay.
                choices:
                    - 'disable'
                    - 'enable'
            app-category:
                type: raw
                description: (list or str) Deprecated, please rename it to app_category. App category.
            app-group:
                type: raw
                description: (list or str) Deprecated, please rename it to app_group. App group.
            application:
                type: raw
                description: (list) Application.
            application-charts:
                type: list
                elements: str
                description: Deprecated, please rename it to application_charts. Application charts.
                choices:
                    - 'top10-app'
                    - 'top10-p2p-user'
                    - 'top10-media-user'
            application-list:
                type: str
                description: Deprecated, please rename it to application_list. Application list.
            auth-cert:
                type: str
                description: Deprecated, please rename it to auth_cert. Auth cert.
            auth-method:
                type: str
                description: Deprecated, please rename it to auth_method. Auth method.
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
                description: Deprecated, please rename it to auth_path. Auth path.
                choices:
                    - 'disable'
                    - 'enable'
            auth-portal:
                type: str
                description: Deprecated, please rename it to auth_portal. Auth portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth-redirect-addr:
                type: str
                description: Deprecated, please rename it to auth_redirect_addr. Auth redirect addr.
            auto-asic-offload:
                type: str
                description: Deprecated, please rename it to auto_asic_offload. Auto asic offload.
                choices:
                    - 'disable'
                    - 'enable'
            av-profile:
                type: str
                description: Deprecated, please rename it to av_profile. Av profile.
            bandwidth:
                type: str
                description: Bandwidth.
                choices:
                    - 'disable'
                    - 'enable'
            block-notification:
                type: str
                description: Deprecated, please rename it to block_notification. Block notification.
                choices:
                    - 'disable'
                    - 'enable'
            captive-portal-exempt:
                type: str
                description: Deprecated, please rename it to captive_portal_exempt. Captive portal exempt.
                choices:
                    - 'disable'
                    - 'enable'
            capture-packet:
                type: str
                description: Deprecated, please rename it to capture_packet. Capture packet.
                choices:
                    - 'disable'
                    - 'enable'
            casi-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to casi_profile. Casi profile.
            central-nat:
                type: str
                description: Deprecated, please rename it to central_nat. Central nat.
                choices:
                    - 'disable'
                    - 'enable'
            cifs-profile:
                type: str
                description: Deprecated, please rename it to cifs_profile. Cifs profile.
            client-reputation:
                type: str
                description: Deprecated, please rename it to client_reputation. Client reputation.
                choices:
                    - 'disable'
                    - 'enable'
            client-reputation-mode:
                type: str
                description: Deprecated, please rename it to client_reputation_mode. Client reputation mode.
                choices:
                    - 'learning'
                    - 'monitoring'
            comments:
                type: raw
                description: (dict or str) Comments.
            custom-log-fields:
                type: raw
                description: (list or str) Deprecated, please rename it to custom_log_fields. Custom log fields.
            deep-inspection-options:
                type: raw
                description: (list or str) Deprecated, please rename it to deep_inspection_options. Deep inspection options.
            delay-tcp-npu-session:
                type: str
                description: Deprecated, please rename it to delay_tcp_npu_session. Delay tcp npu session.
                choices:
                    - 'disable'
                    - 'enable'
            delay-tcp-npu-sessoin:
                type: str
                description: Deprecated, please rename it to delay_tcp_npu_sessoin. Delay tcp npu sessoin.
                choices:
                    - 'disable'
                    - 'enable'
            device-detection-portal:
                type: str
                description: Deprecated, please rename it to device_detection_portal. Device detection portal.
                choices:
                    - 'disable'
                    - 'enable'
            devices:
                type: raw
                description: (list or str) Devices.
            diffserv-forward:
                type: str
                description: Deprecated, please rename it to diffserv_forward. Diffserv forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv-reverse:
                type: str
                description: Deprecated, please rename it to diffserv_reverse. Diffserv reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode-forward:
                type: str
                description: Deprecated, please rename it to diffservcode_forward. Diffservcode forward.
            diffservcode-rev:
                type: str
                description: Deprecated, please rename it to diffservcode_rev. Diffservcode rev.
            disclaimer:
                type: str
                description: Disclaimer.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'user'
                    - 'domain'
                    - 'policy'
            dlp-sensor:
                type: raw
                description: (list or str) Deprecated, please rename it to dlp_sensor. Dlp sensor.
            dnsfilter-profile:
                type: str
                description: Deprecated, please rename it to dnsfilter_profile. Dnsfilter profile.
            dponly:
                type: str
                description: Dponly.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-match:
                type: str
                description: Deprecated, please rename it to dscp_match. Dscp match.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-negate:
                type: str
                description: Deprecated, please rename it to dscp_negate. Dscp negate.
                choices:
                    - 'disable'
                    - 'enable'
            dscp-value:
                type: str
                description: Deprecated, please rename it to dscp_value. Dscp value.
            dsri:
                type: str
                description: Dsri.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Dstaddr.
            dstaddr-negate:
                type: str
                description: Deprecated, please rename it to dstaddr_negate. Dstaddr negate.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: raw
                description: (list or str) Dstaddr6.
            dstintf:
                type: raw
                description: (list or str) Dstintf.
            dynamic-profile:
                type: str
                description: Deprecated, please rename it to dynamic_profile. Dynamic profile.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile-access:
                type: list
                elements: str
                description: Deprecated, please rename it to dynamic_profile_access. Dynamic profile access.
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
                description: Deprecated, please rename it to dynamic_profile_fallthrough. Dynamic profile fallthrough.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic-profile-group:
                type: raw
                description: (list or str) Deprecated, please rename it to dynamic_profile_group. Dynamic profile group.
            email-collect:
                type: str
                description: Deprecated, please rename it to email_collect. Email collect.
                choices:
                    - 'disable'
                    - 'enable'
            email-collection-portal:
                type: str
                description: Deprecated, please rename it to email_collection_portal. Email collection portal.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter-profile:
                type: str
                description: Deprecated, please rename it to emailfilter_profile. Emailfilter profile.
            endpoint-check:
                type: str
                description: Deprecated, please rename it to endpoint_check. Endpoint check.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-compliance:
                type: str
                description: Deprecated, please rename it to endpoint_compliance. Endpoint compliance.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint-keepalive-interface:
                type: raw
                description: (list or str) Deprecated, please rename it to endpoint_keepalive_interface. Endpoint keepalive interface.
            endpoint-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to endpoint_profile. Endpoint profile.
            failed-connection:
                type: str
                description: Deprecated, please rename it to failed_connection. Failed connection.
                choices:
                    - 'disable'
                    - 'enable'
            fall-through-unauthenticated:
                type: str
                description: Deprecated, please rename it to fall_through_unauthenticated. Fall through unauthenticated.
                choices:
                    - 'disable'
                    - 'enable'
            firewall-session-dirty:
                type: str
                description: Deprecated, please rename it to firewall_session_dirty. Firewall session dirty.
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: Fixedport.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient-compliance-devices:
                type: list
                elements: str
                description: Deprecated, please rename it to forticlient_compliance_devices. Forticlient compliance devices.
                choices:
                    - 'windows-pc'
                    - 'mac'
                    - 'iphone-ipad'
                    - 'android'
            forticlient-compliance-enforcement-portal:
                type: str
                description: Deprecated, please rename it to forticlient_compliance_enforcement_portal. Forticlient compliance enforcement portal.
                choices:
                    - 'disable'
                    - 'enable'
            fsae:
                type: str
                description: Fsae.
                choices:
                    - 'disable'
                    - 'enable'
            fsae-server-for-ntlm:
                type: raw
                description: (list or str) Deprecated, please rename it to fsae_server_for_ntlm. Fsae server for ntlm.
            fsso:
                type: str
                description: Fsso.
                choices:
                    - 'disable'
                    - 'enable'
            fsso-agent-for-ntlm:
                type: str
                description: Deprecated, please rename it to fsso_agent_for_ntlm. Fsso agent for ntlm.
            geo-location:
                type: str
                description: Deprecated, please rename it to geo_location. Geo location.
                choices:
                    - 'disable'
                    - 'enable'
            geoip-anycast:
                type: str
                description: Deprecated, please rename it to geoip_anycast. Geoip anycast.
                choices:
                    - 'disable'
                    - 'enable'
            global-label:
                type: str
                description: Deprecated, please rename it to global_label. Global label.
            groups:
                type: raw
                description: (list or str) Groups.
            gtp-profile:
                type: str
                description: Deprecated, please rename it to gtp_profile. Gtp profile.
            http-policy-redirect:
                type: str
                description: Deprecated, please rename it to http_policy_redirect. Http policy redirect.
                choices:
                    - 'disable'
                    - 'enable'
            icap-profile:
                type: str
                description: Deprecated, please rename it to icap_profile. Icap profile.
            identity-based:
                type: str
                description: Deprecated, please rename it to identity_based. Identity based.
                choices:
                    - 'disable'
                    - 'enable'
            identity-based-policy:
                type: list
                elements: dict
                description: Deprecated, please rename it to identity_based_policy. Identity based policy.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'deny'
                            - 'accept'
                    application-charts:
                        type: list
                        elements: str
                        description: Deprecated, please rename it to application_charts. Application charts.
                        choices:
                            - 'top10-app'
                            - 'top10-p2p-user'
                            - 'top10-media-user'
                    application-list:
                        type: str
                        description: Deprecated, please rename it to application_list. Application list.
                    av-profile:
                        type: str
                        description: Deprecated, please rename it to av_profile. Av profile.
                    capture-packet:
                        type: str
                        description: Deprecated, please rename it to capture_packet. Capture packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    deep-inspection-options:
                        type: str
                        description: Deprecated, please rename it to deep_inspection_options. Deep inspection options.
                    devices:
                        type: str
                        description: Devices.
                    dlp-sensor:
                        type: str
                        description: Deprecated, please rename it to dlp_sensor. Dlp sensor.
                    dstaddr:
                        type: str
                        description: Dstaddr.
                    dstaddr-negate:
                        type: str
                        description: Deprecated, please rename it to dstaddr_negate. Dstaddr negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    endpoint-compliance:
                        type: str
                        description: Deprecated, please rename it to endpoint_compliance. Endpoint compliance.
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: Groups.
                    icap-profile:
                        type: str
                        description: Deprecated, please rename it to icap_profile. Icap profile.
                    id:
                        type: int
                        description: Id.
                    ips-sensor:
                        type: str
                        description: Deprecated, please rename it to ips_sensor. Ips sensor.
                    logtraffic:
                        type: str
                        description: Logtraffic.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'all'
                            - 'utm'
                    logtraffic-app:
                        type: str
                        description: Deprecated, please rename it to logtraffic_app. Logtraffic app.
                        choices:
                            - 'disable'
                            - 'enable'
                    logtraffic-start:
                        type: str
                        description: Deprecated, please rename it to logtraffic_start. Logtraffic start.
                        choices:
                            - 'disable'
                            - 'enable'
                    mms-profile:
                        type: str
                        description: Deprecated, please rename it to mms_profile. Mms profile.
                    per-ip-shaper:
                        type: str
                        description: Deprecated, please rename it to per_ip_shaper. Per ip shaper.
                    profile-group:
                        type: str
                        description: Deprecated, please rename it to profile_group. Profile group.
                    profile-protocol-options:
                        type: str
                        description: Deprecated, please rename it to profile_protocol_options. Profile protocol options.
                    profile-type:
                        type: str
                        description: Deprecated, please rename it to profile_type. Profile type.
                        choices:
                            - 'single'
                            - 'group'
                    replacemsg-group:
                        type: str
                        description: Deprecated, please rename it to replacemsg_group. Replacemsg group.
                    schedule:
                        type: str
                        description: Schedule.
                    send-deny-packet:
                        type: str
                        description: Deprecated, please rename it to send_deny_packet. Send deny packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    service:
                        type: str
                        description: Service.
                    service-negate:
                        type: str
                        description: Deprecated, please rename it to service_negate. Service negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    spamfilter-profile:
                        type: str
                        description: Deprecated, please rename it to spamfilter_profile. Spamfilter profile.
                    sslvpn-portal:
                        type: str
                        description: Deprecated, please rename it to sslvpn_portal. Sslvpn portal.
                    sslvpn-realm:
                        type: str
                        description: Deprecated, please rename it to sslvpn_realm. Sslvpn realm.
                    traffic-shaper:
                        type: str
                        description: Deprecated, please rename it to traffic_shaper. Traffic shaper.
                    traffic-shaper-reverse:
                        type: str
                        description: Deprecated, please rename it to traffic_shaper_reverse. Traffic shaper reverse.
                    users:
                        type: str
                        description: Users.
                    utm-status:
                        type: str
                        description: Deprecated, please rename it to utm_status. Utm status.
                        choices:
                            - 'disable'
                            - 'enable'
                    voip-profile:
                        type: str
                        description: Deprecated, please rename it to voip_profile. Voip profile.
                    webfilter-profile:
                        type: str
                        description: Deprecated, please rename it to webfilter_profile. Webfilter profile.
            identity-based-route:
                type: str
                description: Deprecated, please rename it to identity_based_route. Identity based route.
            identity-from:
                type: str
                description: Deprecated, please rename it to identity_from. Identity from.
                choices:
                    - 'auth'
                    - 'device'
            inbound:
                type: str
                description: Inbound.
                choices:
                    - 'disable'
                    - 'enable'
            inspection-mode:
                type: str
                description: Deprecated, please rename it to inspection_mode. Inspection mode.
                choices:
                    - 'proxy'
                    - 'flow'
            internet-service:
                type: str
                description: Deprecated, please rename it to internet_service. Internet service.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom. Internet service custom.
            internet-service-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom_group. Internet service custom group.
            internet-service-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_group. Internet service group.
            internet-service-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_id. Internet service id.
            internet-service-negate:
                type: str
                description: Deprecated, please rename it to internet_service_negate. Internet service negate.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: Deprecated, please rename it to internet_service_src. Internet service src.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom. Internet service src custom.
            internet-service-src-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom_group. Internet service src custom group.
            internet-service-src-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_group. Internet service src group.
            internet-service-src-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_id. Internet service src id.
            internet-service-src-negate:
                type: str
                description: Deprecated, please rename it to internet_service_src_negate. Internet service src negate.
                choices:
                    - 'disable'
                    - 'enable'
            ip-based:
                type: str
                description: Deprecated, please rename it to ip_based. Ip based.
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: Ippool.
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. Ips sensor.
            label:
                type: str
                description: Label.
            learning-mode:
                type: str
                description: Deprecated, please rename it to learning_mode. Learning mode.
                choices:
                    - 'disable'
                    - 'enable'
            log-unmatched-traffic:
                type: str
                description: Deprecated, please rename it to log_unmatched_traffic. Log unmatched traffic.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic:
                type: str
                description: Logtraffic.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            logtraffic-app:
                type: str
                description: Deprecated, please rename it to logtraffic_app. Logtraffic app.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic-start:
                type: str
                description: Deprecated, please rename it to logtraffic_start. Logtraffic start.
                choices:
                    - 'disable'
                    - 'enable'
            match-vip:
                type: str
                description: Deprecated, please rename it to match_vip. Match vip.
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to mms_profile. Mms profile.
            name:
                type: str
                description: Name.
            nat:
                type: str
                description: Nat.
                choices:
                    - 'disable'
                    - 'enable'
            natinbound:
                type: str
                description: Natinbound.
                choices:
                    - 'disable'
                    - 'enable'
            natip:
                type: str
                description: Natip.
            natoutbound:
                type: str
                description: Natoutbound.
                choices:
                    - 'disable'
                    - 'enable'
            np-acceleration:
                type: str
                description: Deprecated, please rename it to np_acceleration. Np acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm:
                type: str
                description: Ntlm.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm-enabled-browsers:
                type: raw
                description: (list) Deprecated, please rename it to ntlm_enabled_browsers. Ntlm enabled browsers.
            ntlm-guest:
                type: str
                description: Deprecated, please rename it to ntlm_guest. Ntlm guest.
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: Outbound.
                choices:
                    - 'disable'
                    - 'enable'
            per-ip-shaper:
                type: str
                description: Deprecated, please rename it to per_ip_shaper. Per ip shaper.
            permit-any-host:
                type: str
                description: Deprecated, please rename it to permit_any_host. Permit any host.
                choices:
                    - 'disable'
                    - 'enable'
            permit-stun-host:
                type: str
                description: Deprecated, please rename it to permit_stun_host. Permit stun host.
                choices:
                    - 'disable'
                    - 'enable'
            policyid:
                type: int
                description: Policyid.
                required: true
            poolname:
                type: raw
                description: (list or str) Poolname.
            profile-group:
                type: str
                description: Deprecated, please rename it to profile_group. Profile group.
            profile-protocol-options:
                type: str
                description: Deprecated, please rename it to profile_protocol_options. Profile protocol options.
            profile-type:
                type: str
                description: Deprecated, please rename it to profile_type. Profile type.
                choices:
                    - 'single'
                    - 'group'
            radius-mac-auth-bypass:
                type: str
                description: Deprecated, please rename it to radius_mac_auth_bypass. Radius mac auth bypass.
                choices:
                    - 'disable'
                    - 'enable'
            redirect-url:
                type: str
                description: Deprecated, please rename it to redirect_url. Redirect url.
            replacemsg-group:
                type: raw
                description: (list or str) Deprecated, please rename it to replacemsg_group. Replacemsg group.
            replacemsg-override-group:
                type: str
                description: Deprecated, please rename it to replacemsg_override_group. Replacemsg override group.
            reputation-direction:
                type: str
                description: Deprecated, please rename it to reputation_direction. Reputation direction.
                choices:
                    - 'source'
                    - 'destination'
            reputation-minimum:
                type: int
                description: Deprecated, please rename it to reputation_minimum. Reputation minimum.
            require-tfa:
                type: str
                description: Deprecated, please rename it to require_tfa. Require tfa.
                choices:
                    - 'disable'
                    - 'enable'
            rsso:
                type: str
                description: Rsso.
                choices:
                    - 'disable'
                    - 'enable'
            rtp-addr:
                type: raw
                description: (list or str) Deprecated, please rename it to rtp_addr. Rtp addr.
            rtp-nat:
                type: str
                description: Deprecated, please rename it to rtp_nat. Rtp nat.
                choices:
                    - 'disable'
                    - 'enable'
            scan-botnet-connections:
                type: str
                description: Deprecated, please rename it to scan_botnet_connections. Scan botnet connections.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: Schedule.
            schedule-timeout:
                type: str
                description: Deprecated, please rename it to schedule_timeout. Schedule timeout.
                choices:
                    - 'disable'
                    - 'enable'
            send-deny-packet:
                type: str
                description: Deprecated, please rename it to send_deny_packet. Send deny packet.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: raw
                description: (list or str) Service.
            service-negate:
                type: str
                description: Deprecated, please rename it to service_negate. Service negate.
                choices:
                    - 'disable'
                    - 'enable'
            session-ttl:
                type: raw
                description: (int or str) Deprecated, please rename it to session_ttl. Session ttl.
            sessions:
                type: str
                description: Sessions.
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter-profile:
                type: raw
                description: (list or str) Deprecated, please rename it to spamfilter_profile. Spamfilter profile.
            srcaddr:
                type: raw
                description: (list or str) Srcaddr.
            srcaddr-negate:
                type: str
                description: Deprecated, please rename it to srcaddr_negate. Srcaddr negate.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: raw
                description: (list or str) Srcaddr6.
            srcintf:
                type: raw
                description: (list or str) Srcintf.
            ssh-filter-profile:
                type: str
                description: Deprecated, please rename it to ssh_filter_profile. Ssh filter profile.
            ssh-policy-redirect:
                type: str
                description: Deprecated, please rename it to ssh_policy_redirect. Ssh policy redirect.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror:
                type: str
                description: Deprecated, please rename it to ssl_mirror. Ssl mirror.
                choices:
                    - 'disable'
                    - 'enable'
            ssl-mirror-intf:
                type: raw
                description: (list or str) Deprecated, please rename it to ssl_mirror_intf. Ssl mirror intf.
            ssl-ssh-profile:
                type: str
                description: Deprecated, please rename it to ssl_ssh_profile. Ssl ssh profile.
            sslvpn-auth:
                type: str
                description: Deprecated, please rename it to sslvpn_auth. Sslvpn auth.
                choices:
                    - 'any'
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs+'
            sslvpn-ccert:
                type: str
                description: Deprecated, please rename it to sslvpn_ccert. Sslvpn ccert.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-cipher:
                type: str
                description: Deprecated, please rename it to sslvpn_cipher. Sslvpn cipher.
                choices:
                    - 'any'
                    - 'high'
                    - 'medium'
            sso-auth-method:
                type: str
                description: Deprecated, please rename it to sso_auth_method. Sso auth method.
                choices:
                    - 'fsso'
                    - 'rsso'
            status:
                type: str
                description: Status.
                choices:
                    - 'disable'
                    - 'enable'
            tags:
                type: raw
                description: (list or str) Tags.
            tcp-mss-receiver:
                type: int
                description: Deprecated, please rename it to tcp_mss_receiver. Tcp mss receiver.
            tcp-mss-sender:
                type: int
                description: Deprecated, please rename it to tcp_mss_sender. Tcp mss sender.
            tcp-reset:
                type: str
                description: Deprecated, please rename it to tcp_reset. Tcp reset.
                choices:
                    - 'disable'
                    - 'enable'
            tcp-session-without-syn:
                type: str
                description: Deprecated, please rename it to tcp_session_without_syn. Tcp session without syn.
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout-send-rst:
                type: str
                description: Deprecated, please rename it to timeout_send_rst. Timeout send rst.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: Tos.
            tos-mask:
                type: str
                description: Deprecated, please rename it to tos_mask. Tos mask.
            tos-negate:
                type: str
                description: Deprecated, please rename it to tos_negate. Tos negate.
                choices:
                    - 'disable'
                    - 'enable'
            traffic-shaper:
                type: str
                description: Deprecated, please rename it to traffic_shaper. Traffic shaper.
            traffic-shaper-reverse:
                type: str
                description: Deprecated, please rename it to traffic_shaper_reverse. Traffic shaper reverse.
            transaction-based:
                type: str
                description: Deprecated, please rename it to transaction_based. Transaction based.
                choices:
                    - 'disable'
                    - 'enable'
            url-category:
                type: raw
                description: (list or str) Deprecated, please rename it to url_category. Url category.
            users:
                type: raw
                description: (list or str) Users.
            utm-inspection-mode:
                type: str
                description: Deprecated, please rename it to utm_inspection_mode. Utm inspection mode.
                choices:
                    - 'proxy'
                    - 'flow'
            utm-status:
                type: str
                description: Deprecated, please rename it to utm_status. Utm status.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Uuid.
            vlan-cos-fwd:
                type: int
                description: Deprecated, please rename it to vlan_cos_fwd. Vlan cos fwd.
            vlan-cos-rev:
                type: int
                description: Deprecated, please rename it to vlan_cos_rev. Vlan cos rev.
            vlan-filter:
                type: str
                description: Deprecated, please rename it to vlan_filter. Vlan filter.
            voip-profile:
                type: str
                description: Deprecated, please rename it to voip_profile. Voip profile.
            vpntunnel:
                type: str
                description: Vpntunnel.
            waf-profile:
                type: str
                description: Deprecated, please rename it to waf_profile. Waf profile.
            wanopt:
                type: str
                description: Wanopt.
                choices:
                    - 'disable'
                    - 'enable'
            wanopt-detection:
                type: str
                description: Deprecated, please rename it to wanopt_detection. Wanopt detection.
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt-passive-opt:
                type: str
                description: Deprecated, please rename it to wanopt_passive_opt. Wanopt passive opt.
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt-peer:
                type: str
                description: Deprecated, please rename it to wanopt_peer. Wanopt peer.
            wanopt-profile:
                type: str
                description: Deprecated, please rename it to wanopt_profile. Wanopt profile.
            wccp:
                type: str
                description: Wccp.
                choices:
                    - 'disable'
                    - 'enable'
            web-auth-cookie:
                type: str
                description: Deprecated, please rename it to web_auth_cookie. Web auth cookie.
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: Webcache.
                choices:
                    - 'disable'
                    - 'enable'
            webcache-https:
                type: str
                description: Deprecated, please rename it to webcache_https. Webcache https.
                choices:
                    - 'disable'
                    - 'ssl-server'
                    - 'any'
                    - 'enable'
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile. Webfilter profile.
            webproxy-forward-server:
                type: str
                description: Deprecated, please rename it to webproxy_forward_server. Webproxy forward server.
            webproxy-profile:
                type: str
                description: Deprecated, please rename it to webproxy_profile. Webproxy profile.
            wsso:
                type: str
                description: Wsso.
                choices:
                    - 'disable'
                    - 'enable'
            fsso-groups:
                type: raw
                description: (list or str) Deprecated, please rename it to fsso_groups. Fsso groups.
            match-vip-only:
                type: str
                description: Deprecated, please rename it to match_vip_only. Match vip only.
                choices:
                    - 'disable'
                    - 'enable'
            np-accelation:
                type: str
                description: Deprecated, please rename it to np_accelation. Np accelation.
                choices:
                    - 'disable'
                    - 'enable'
            best-route:
                type: str
                description: Deprecated, please rename it to best_route. Best route.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted-traffic-mirror:
                type: str
                description: Deprecated, please rename it to decrypted_traffic_mirror. Decrypted traffic mirror.
            geoip-match:
                type: str
                description: Deprecated, please rename it to geoip_match. Geoip match.
                choices:
                    - 'physical-location'
                    - 'registered-location'
            internet-service-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_name. Internet service name.
            internet-service-src-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_name. Internet service src name.
            poolname6:
                type: raw
                description: (list or str) Poolname6.
            src-vendor-mac:
                type: raw
                description: (list or str) Deprecated, please rename it to src_vendor_mac. Src vendor mac.
            vendor-mac:
                type: raw
                description: (list or str) Deprecated, please rename it to vendor_mac. Vendor mac.
            file-filter-profile:
                type: str
                description: Deprecated, please rename it to file_filter_profile. File filter profile.
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
                description: (list) Deprecated, please rename it to access_proxy. Access proxy.
            dlp-profile:
                type: str
                description: Deprecated, please rename it to dlp_profile. Name of an existing DLP profile.
            dynamic-bypass:
                type: str
                description: Deprecated, please rename it to dynamic_bypass. Dynamic bypass.
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
                description: Deprecated, please rename it to force_proxy. Force proxy.
                choices:
                    - 'disable'
                    - 'enable'
            http-tunnel-auth:
                type: str
                description: Deprecated, please rename it to http_tunnel_auth. Http tunnel auth.
                choices:
                    - 'disable'
                    - 'enable'
            ia-profile:
                type: raw
                description: (list) Deprecated, please rename it to ia_profile. Ia profile.
            isolator-server:
                type: raw
                description: (list) Deprecated, please rename it to isolator_server. Isolator server.
            log-http-transaction:
                type: str
                description: Deprecated, please rename it to log_http_transaction. Log http transaction.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            max-session-per-user:
                type: int
                description: Deprecated, please rename it to max_session_per_user. Max session per user.
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
                description: Deprecated, please rename it to pass_through. Pass through.
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
                description: Deprecated, please rename it to reverse_cache. Reverse cache.
                choices:
                    - 'disable'
                    - 'enable'
            sctp-filter-profile:
                type: str
                description: Deprecated, please rename it to sctp_filter_profile. Name of an existing SCTP filter profile.
            sgt:
                type: raw
                description: (list) Security group tags.
            sgt-check:
                type: str
                description: Deprecated, please rename it to sgt_check. Enable/disable security group tags
                choices:
                    - 'disable'
                    - 'enable'
            tcp-timeout-pid:
                type: raw
                description: (list) Deprecated, please rename it to tcp_timeout_pid. TCP timeout profile ID
            transparent:
                type: str
                description: Transparent.
                choices:
                    - 'disable'
                    - 'enable'
            type:
                type: str
                description: Type.
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
                description: (list) Deprecated, please rename it to udp_timeout_pid. UDP timeout profile ID
            ztna-tags-match-logic:
                type: str
                description: Deprecated, please rename it to ztna_tags_match_logic. Ztna tags match logic.
                choices:
                    - 'or'
                    - 'and'
            uuid-idx:
                type: int
                description: Deprecated, please rename it to uuid_idx. Uuid idx.
            device-ownership:
                type: str
                description: Deprecated, please rename it to device_ownership. Device ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ssh-policy-check:
                type: str
                description: Deprecated, please rename it to ssh_policy_check. Ssh policy check.
                choices:
                    - 'disable'
                    - 'enable'
            extended-log:
                type: str
                description: Deprecated, please rename it to extended_log. Extended log.
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
                description: (list) Deprecated, please rename it to internet_service6_custom. Custom IPv6 Internet Service name.
            internet-service6-custom-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_custom_group. Custom Internet Service6 group name.
            internet-service6-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_group. Internet Service group name.
            internet-service6-name:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_name. IPv6 Internet Service name.
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
                description: (list) Deprecated, please rename it to internet_service6_src_custom. Custom IPv6 Internet Service source name.
            internet-service6-src-custom-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_custom_group. Custom Internet Service6 source group name.
            internet-service6-src-group:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_group. Internet Service6 source group name.
            internet-service6-src-name:
                type: raw
                description: (list) Deprecated, please rename it to internet_service6_src_name. IPv6 Internet Service source name.
            internet-service6-src-negate:
                type: str
                description: Deprecated, please rename it to internet_service6_src_negate. When enabled internet-service6-src specifies what the servic...
                choices:
                    - 'disable'
                    - 'enable'
            network-service-dynamic:
                type: raw
                description: (list) Deprecated, please rename it to network_service_dynamic. Dynamic Network Service name.
            network-service-src-dynamic:
                type: raw
                description: (list) Deprecated, please rename it to network_service_src_dynamic. Dynamic Network Service source name.
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
                description: (list) Deprecated, please rename it to isolator_profile. Isolator profile.
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
                description: (list) Deprecated, please rename it to pcp_poolname. PCP pool names.
            ztna-ems-tag-secondary:
                type: raw
                description: (list) Deprecated, please rename it to ztna_ems_tag_secondary. Source ztna-ems-tag-secondary names.
            casb-profile:
                type: str
                description: Deprecated, please rename it to casb_profile. Name of an existing CASB profile.
            implicit-proxy-detection:
                type: str
                description: Deprecated, please rename it to implicit_proxy_detection. Implicit proxy detection.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-patch-profile:
                type: str
                description: Deprecated, please rename it to virtual_patch_profile. Name of an existing virtual-patch profile.
            detect-https-in-http-request:
                type: str
                description: Deprecated, please rename it to detect_https_in_http_request. Detect https in http request.
                choices:
                    - 'disable'
                    - 'enable'
            diameter-filter-profile:
                type: str
                description: Deprecated, please rename it to diameter_filter_profile. Name of an existing Diameter filter profile.
            redirect-profile:
                type: raw
                description: (list) Deprecated, please rename it to redirect_profile. Redirect profile.
            port-preserve:
                type: str
                description: Deprecated, please rename it to port_preserve. Enable/disable preservation of the original source port from source NAT if ...
                choices:
                    - 'disable'
                    - 'enable'
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
    - name: Configure IPv4 header policies.
      fortinet.fortimanager.fmgr_pkg_header_policy:
        bypass_validation: false
        pkg: ansible
        state: present
        pkg_header_policy:
          action: accept # <value in [deny, accept, ipsec, ...]>
          comments: "ansible-comment"
          dstaddr: gall
          dstintf: any
          name: ansible-test-header
          policyid: 1073741826 # must larger than 2^30(1074741824), since header/footer policy is a special policy
          schedule: galways
          service: gALL
          srcaddr: gall
          srcintf: any
          status: disable

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the IPv4 header policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_header_policy"
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
        '/pm/config/global/pkg/{pkg}/global/header/policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/pkg/{pkg}/global/header/policy/{policy}'
    ]

    url_params = ['pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'pkg': {'required': True, 'type': 'str'},
        'pkg_header_policy': {
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
                'np-accelation': {'v_range': [['6.2.1', '6.4.14']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                'device-ownership': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-policy-check': {'v_range': [['7.0.5', '7.0.12'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-log': {'v_range': [['7.0.11', '7.0.12'], ['7.2.5', '7.2.5'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                'implicit-proxy-detection': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'detect-https-in-http-request': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'redirect-profile': {'v_range': [['7.4.2', '']], 'type': 'raw'},
                'port-preserve': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = [
        {
            'attribute_path': ['pkg_header_policy', 'policyid'],
            'lambda': 'int($) >= 1073741824',
            'fail_action': 'warn',
            'hint_message': 'policyid should be larger than 2^30, i.e. 1073741824, otherwise it will be ignored.'
        }
    ]

    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_header_policy'),
                           supports_check_mode=False)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_curd(argument_specs=module_arg_spec)

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
