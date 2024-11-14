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
                description: Action.
                choices:
                    - 'deny'
                    - 'accept'
                    - 'ipsec'
                    - 'ssl-vpn'
                    - 'redirect'
                    - 'isolate'
            active_auth_method:
                type: str
                description: Active auth method.
                choices:
                    - 'ntlm'
                    - 'basic'
                    - 'digest'
                    - 'form'
            anti_replay:
                type: str
                description: Anti replay.
                choices:
                    - 'disable'
                    - 'enable'
            app_category:
                type: raw
                description: (list or str) App category.
            app_group:
                type: raw
                description: (list or str) App group.
            application:
                type: raw
                description: (list) Application.
            application_charts:
                type: list
                elements: str
                description: Application charts.
                choices:
                    - 'top10-app'
                    - 'top10-p2p-user'
                    - 'top10-media-user'
            application_list:
                type: str
                description: Application list.
            auth_cert:
                type: str
                description: Auth cert.
            auth_method:
                type: str
                description: Auth method.
                choices:
                    - 'basic'
                    - 'digest'
                    - 'ntlm'
                    - 'fsae'
                    - 'form'
                    - 'fsso'
                    - 'rsso'
            auth_path:
                type: str
                description: Auth path.
                choices:
                    - 'disable'
                    - 'enable'
            auth_portal:
                type: str
                description: Auth portal.
                choices:
                    - 'disable'
                    - 'enable'
            auth_redirect_addr:
                type: str
                description: Auth redirect addr.
            auto_asic_offload:
                type: str
                description: Auto asic offload.
                choices:
                    - 'disable'
                    - 'enable'
            av_profile:
                type: str
                description: Av profile.
            bandwidth:
                type: str
                description: Bandwidth.
                choices:
                    - 'disable'
                    - 'enable'
            block_notification:
                type: str
                description: Block notification.
                choices:
                    - 'disable'
                    - 'enable'
            captive_portal_exempt:
                type: str
                description: Captive portal exempt.
                choices:
                    - 'disable'
                    - 'enable'
            capture_packet:
                type: str
                description: Capture packet.
                choices:
                    - 'disable'
                    - 'enable'
            casi_profile:
                type: raw
                description: (list or str) Casi profile.
            central_nat:
                type: str
                description: Central nat.
                choices:
                    - 'disable'
                    - 'enable'
            cifs_profile:
                type: str
                description: Cifs profile.
            client_reputation:
                type: str
                description: Client reputation.
                choices:
                    - 'disable'
                    - 'enable'
            client_reputation_mode:
                type: str
                description: Client reputation mode.
                choices:
                    - 'learning'
                    - 'monitoring'
            comments:
                type: raw
                description: (dict or str) Comments.
            custom_log_fields:
                type: raw
                description: (list or str) Custom log fields.
            deep_inspection_options:
                type: raw
                description: (list or str) Deep inspection options.
            delay_tcp_npu_session:
                type: str
                description: Delay tcp npu session.
                choices:
                    - 'disable'
                    - 'enable'
            delay_tcp_npu_sessoin:
                type: str
                description: Delay tcp npu sessoin.
                choices:
                    - 'disable'
                    - 'enable'
            device_detection_portal:
                type: str
                description: Device detection portal.
                choices:
                    - 'disable'
                    - 'enable'
            devices:
                type: raw
                description: (list or str) Devices.
            diffserv_forward:
                type: str
                description: Diffserv forward.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_reverse:
                type: str
                description: Diffserv reverse.
                choices:
                    - 'disable'
                    - 'enable'
            diffservcode_forward:
                type: str
                description: Diffservcode forward.
            diffservcode_rev:
                type: str
                description: Diffservcode rev.
            disclaimer:
                type: str
                description: Disclaimer.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'user'
                    - 'domain'
                    - 'policy'
            dlp_sensor:
                type: raw
                description: (list or str) Dlp sensor.
            dnsfilter_profile:
                type: str
                description: Dnsfilter profile.
            dponly:
                type: str
                description: Dponly.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_match:
                type: str
                description: Dscp match.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_negate:
                type: str
                description: Dscp negate.
                choices:
                    - 'disable'
                    - 'enable'
            dscp_value:
                type: str
                description: Dscp value.
            dsri:
                type: str
                description: Dsri.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Dstaddr.
            dstaddr_negate:
                type: str
                description: Dstaddr negate.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6:
                type: raw
                description: (list or str) Dstaddr6.
            dstintf:
                type: raw
                description: (list or str) Dstintf.
            dynamic_profile:
                type: str
                description: Dynamic profile.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_profile_access:
                type: list
                elements: str
                description: Dynamic profile access.
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
            dynamic_profile_fallthrough:
                type: str
                description: Dynamic profile fallthrough.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_profile_group:
                type: raw
                description: (list or str) Dynamic profile group.
            email_collect:
                type: str
                description: Email collect.
                choices:
                    - 'disable'
                    - 'enable'
            email_collection_portal:
                type: str
                description: Email collection portal.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter_profile:
                type: str
                description: Emailfilter profile.
            endpoint_check:
                type: str
                description: Endpoint check.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint_compliance:
                type: str
                description: Endpoint compliance.
                choices:
                    - 'disable'
                    - 'enable'
            endpoint_keepalive_interface:
                type: raw
                description: (list or str) Endpoint keepalive interface.
            endpoint_profile:
                type: raw
                description: (list or str) Endpoint profile.
            failed_connection:
                type: str
                description: Failed connection.
                choices:
                    - 'disable'
                    - 'enable'
            fall_through_unauthenticated:
                type: str
                description: Fall through unauthenticated.
                choices:
                    - 'disable'
                    - 'enable'
            firewall_session_dirty:
                type: str
                description: Firewall session dirty.
                choices:
                    - 'check-all'
                    - 'check-new'
            fixedport:
                type: str
                description: Fixedport.
                choices:
                    - 'disable'
                    - 'enable'
            forticlient_compliance_devices:
                type: list
                elements: str
                description: Forticlient compliance devices.
                choices:
                    - 'windows-pc'
                    - 'mac'
                    - 'iphone-ipad'
                    - 'android'
            forticlient_compliance_enforcement_portal:
                type: str
                description: Forticlient compliance enforcement portal.
                choices:
                    - 'disable'
                    - 'enable'
            fsae:
                type: str
                description: Fsae.
                choices:
                    - 'disable'
                    - 'enable'
            fsae_server_for_ntlm:
                type: raw
                description: (list or str) Fsae server for ntlm.
            fsso:
                type: str
                description: Fsso.
                choices:
                    - 'disable'
                    - 'enable'
            fsso_agent_for_ntlm:
                type: str
                description: Fsso agent for ntlm.
            geo_location:
                type: str
                description: Geo location.
                choices:
                    - 'disable'
                    - 'enable'
            geoip_anycast:
                type: str
                description: Geoip anycast.
                choices:
                    - 'disable'
                    - 'enable'
            global_label:
                type: str
                description: Global label.
            groups:
                type: raw
                description: (list or str) Groups.
            gtp_profile:
                type: str
                description: Gtp profile.
            http_policy_redirect:
                type: str
                description: Http policy redirect.
                choices:
                    - 'disable'
                    - 'enable'
            icap_profile:
                type: str
                description: Icap profile.
            identity_based:
                type: str
                description: Identity based.
                choices:
                    - 'disable'
                    - 'enable'
            identity_based_policy:
                type: list
                elements: dict
                description: Identity based policy.
                suboptions:
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'deny'
                            - 'accept'
                    application_charts:
                        type: list
                        elements: str
                        description: Application charts.
                        choices:
                            - 'top10-app'
                            - 'top10-p2p-user'
                            - 'top10-media-user'
                    application_list:
                        type: str
                        description: Application list.
                    av_profile:
                        type: str
                        description: Av profile.
                    capture_packet:
                        type: str
                        description: Capture packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    deep_inspection_options:
                        type: str
                        description: Deep inspection options.
                    devices:
                        type: str
                        description: Devices.
                    dlp_sensor:
                        type: str
                        description: Dlp sensor.
                    dstaddr:
                        type: str
                        description: Dstaddr.
                    dstaddr_negate:
                        type: str
                        description: Dstaddr negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    endpoint_compliance:
                        type: str
                        description: Endpoint compliance.
                        choices:
                            - 'disable'
                            - 'enable'
                    groups:
                        type: str
                        description: Groups.
                    icap_profile:
                        type: str
                        description: Icap profile.
                    id:
                        type: int
                        description: Id.
                    ips_sensor:
                        type: str
                        description: Ips sensor.
                    logtraffic:
                        type: str
                        description: Logtraffic.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'all'
                            - 'utm'
                    logtraffic_app:
                        type: str
                        description: Logtraffic app.
                        choices:
                            - 'disable'
                            - 'enable'
                    logtraffic_start:
                        type: str
                        description: Logtraffic start.
                        choices:
                            - 'disable'
                            - 'enable'
                    mms_profile:
                        type: str
                        description: Mms profile.
                    per_ip_shaper:
                        type: str
                        description: Per ip shaper.
                    profile_group:
                        type: str
                        description: Profile group.
                    profile_protocol_options:
                        type: str
                        description: Profile protocol options.
                    profile_type:
                        type: str
                        description: Profile type.
                        choices:
                            - 'single'
                            - 'group'
                    replacemsg_group:
                        type: str
                        description: Replacemsg group.
                    schedule:
                        type: str
                        description: Schedule.
                    send_deny_packet:
                        type: str
                        description: Send deny packet.
                        choices:
                            - 'disable'
                            - 'enable'
                    service:
                        type: str
                        description: Service.
                    service_negate:
                        type: str
                        description: Service negate.
                        choices:
                            - 'disable'
                            - 'enable'
                    spamfilter_profile:
                        type: str
                        description: Spamfilter profile.
                    sslvpn_portal:
                        type: str
                        description: Sslvpn portal.
                    sslvpn_realm:
                        type: str
                        description: Sslvpn realm.
                    traffic_shaper:
                        type: str
                        description: Traffic shaper.
                    traffic_shaper_reverse:
                        type: str
                        description: Traffic shaper reverse.
                    users:
                        type: str
                        description: Users.
                    utm_status:
                        type: str
                        description: Utm status.
                        choices:
                            - 'disable'
                            - 'enable'
                    voip_profile:
                        type: str
                        description: Voip profile.
                    webfilter_profile:
                        type: str
                        description: Webfilter profile.
            identity_based_route:
                type: str
                description: Identity based route.
            identity_from:
                type: str
                description: Identity from.
                choices:
                    - 'auth'
                    - 'device'
            inbound:
                type: str
                description: Inbound.
                choices:
                    - 'disable'
                    - 'enable'
            inspection_mode:
                type: str
                description: Inspection mode.
                choices:
                    - 'proxy'
                    - 'flow'
            internet_service:
                type: str
                description: Internet service.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_custom:
                type: raw
                description: (list or str) Internet service custom.
            internet_service_custom_group:
                type: raw
                description: (list or str) Internet service custom group.
            internet_service_group:
                type: raw
                description: (list or str) Internet service group.
            internet_service_id:
                type: raw
                description: (list or str) Internet service id.
            internet_service_negate:
                type: str
                description: Internet service negate.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src:
                type: str
                description: Internet service src.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service_src_custom:
                type: raw
                description: (list or str) Internet service src custom.
            internet_service_src_custom_group:
                type: raw
                description: (list or str) Internet service src custom group.
            internet_service_src_group:
                type: raw
                description: (list or str) Internet service src group.
            internet_service_src_id:
                type: raw
                description: (list or str) Internet service src id.
            internet_service_src_negate:
                type: str
                description: Internet service src negate.
                choices:
                    - 'disable'
                    - 'enable'
            ip_based:
                type: str
                description: Ip based.
                choices:
                    - 'disable'
                    - 'enable'
            ippool:
                type: str
                description: Ippool.
                choices:
                    - 'disable'
                    - 'enable'
            ips_sensor:
                type: str
                description: Ips sensor.
            label:
                type: str
                description: Label.
            learning_mode:
                type: str
                description: Learning mode.
                choices:
                    - 'disable'
                    - 'enable'
            log_unmatched_traffic:
                type: str
                description: Log unmatched traffic.
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
            logtraffic_app:
                type: str
                description: Logtraffic app.
                choices:
                    - 'disable'
                    - 'enable'
            logtraffic_start:
                type: str
                description: Logtraffic start.
                choices:
                    - 'disable'
                    - 'enable'
            match_vip:
                type: str
                description: Match vip.
                choices:
                    - 'disable'
                    - 'enable'
            mms_profile:
                type: raw
                description: (list or str) Mms profile.
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
            np_acceleration:
                type: str
                description: Np acceleration.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm:
                type: str
                description: Ntlm.
                choices:
                    - 'disable'
                    - 'enable'
            ntlm_enabled_browsers:
                type: raw
                description: (list) Ntlm enabled browsers.
            ntlm_guest:
                type: str
                description: Ntlm guest.
                choices:
                    - 'disable'
                    - 'enable'
            outbound:
                type: str
                description: Outbound.
                choices:
                    - 'disable'
                    - 'enable'
            per_ip_shaper:
                type: str
                description: Per ip shaper.
            permit_any_host:
                type: str
                description: Permit any host.
                choices:
                    - 'disable'
                    - 'enable'
            permit_stun_host:
                type: str
                description: Permit stun host.
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
            profile_group:
                type: str
                description: Profile group.
            profile_protocol_options:
                type: str
                description: Profile protocol options.
            profile_type:
                type: str
                description: Profile type.
                choices:
                    - 'single'
                    - 'group'
            radius_mac_auth_bypass:
                type: str
                description: Radius mac auth bypass.
                choices:
                    - 'disable'
                    - 'enable'
            redirect_url:
                type: str
                description: Redirect url.
            replacemsg_group:
                type: raw
                description: (list or str) Replacemsg group.
            replacemsg_override_group:
                type: str
                description: Replacemsg override group.
            reputation_direction:
                type: str
                description: Reputation direction.
                choices:
                    - 'source'
                    - 'destination'
            reputation_minimum:
                type: int
                description: Reputation minimum.
            require_tfa:
                type: str
                description: Require tfa.
                choices:
                    - 'disable'
                    - 'enable'
            rsso:
                type: str
                description: Rsso.
                choices:
                    - 'disable'
                    - 'enable'
            rtp_addr:
                type: raw
                description: (list or str) Rtp addr.
            rtp_nat:
                type: str
                description: Rtp nat.
                choices:
                    - 'disable'
                    - 'enable'
            scan_botnet_connections:
                type: str
                description: Scan botnet connections.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            schedule:
                type: str
                description: Schedule.
            schedule_timeout:
                type: str
                description: Schedule timeout.
                choices:
                    - 'disable'
                    - 'enable'
            send_deny_packet:
                type: str
                description: Send deny packet.
                choices:
                    - 'disable'
                    - 'enable'
            service:
                type: raw
                description: (list or str) Service.
            service_negate:
                type: str
                description: Service negate.
                choices:
                    - 'disable'
                    - 'enable'
            session_ttl:
                type: raw
                description: (int or str) Session ttl.
            sessions:
                type: str
                description: Sessions.
                choices:
                    - 'disable'
                    - 'enable'
            spamfilter_profile:
                type: raw
                description: (list or str) Spamfilter profile.
            srcaddr:
                type: raw
                description: (list or str) Srcaddr.
            srcaddr_negate:
                type: str
                description: Srcaddr negate.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr6:
                type: raw
                description: (list or str) Srcaddr6.
            srcintf:
                type: raw
                description: (list or str) Srcintf.
            ssh_filter_profile:
                type: str
                description: Ssh filter profile.
            ssh_policy_redirect:
                type: str
                description: Ssh policy redirect.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_mirror:
                type: str
                description: Ssl mirror.
                choices:
                    - 'disable'
                    - 'enable'
            ssl_mirror_intf:
                type: raw
                description: (list or str) Ssl mirror intf.
            ssl_ssh_profile:
                type: str
                description: Ssl ssh profile.
            sslvpn_auth:
                type: str
                description: Sslvpn auth.
                choices:
                    - 'any'
                    - 'local'
                    - 'radius'
                    - 'ldap'
                    - 'tacacs+'
            sslvpn_ccert:
                type: str
                description: Sslvpn ccert.
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn_cipher:
                type: str
                description: Sslvpn cipher.
                choices:
                    - 'any'
                    - 'high'
                    - 'medium'
            sso_auth_method:
                type: str
                description: Sso auth method.
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
            tcp_mss_receiver:
                type: int
                description: Tcp mss receiver.
            tcp_mss_sender:
                type: int
                description: Tcp mss sender.
            tcp_reset:
                type: str
                description: Tcp reset.
                choices:
                    - 'disable'
                    - 'enable'
            tcp_session_without_syn:
                type: str
                description: Tcp session without syn.
                choices:
                    - 'all'
                    - 'data-only'
                    - 'disable'
            timeout_send_rst:
                type: str
                description: Timeout send rst.
                choices:
                    - 'disable'
                    - 'enable'
            tos:
                type: str
                description: Tos.
            tos_mask:
                type: str
                description: Tos mask.
            tos_negate:
                type: str
                description: Tos negate.
                choices:
                    - 'disable'
                    - 'enable'
            traffic_shaper:
                type: str
                description: Traffic shaper.
            traffic_shaper_reverse:
                type: str
                description: Traffic shaper reverse.
            transaction_based:
                type: str
                description: Transaction based.
                choices:
                    - 'disable'
                    - 'enable'
            url_category:
                type: raw
                description: (list or str) Url category.
            users:
                type: raw
                description: (list or str) Users.
            utm_inspection_mode:
                type: str
                description: Utm inspection mode.
                choices:
                    - 'proxy'
                    - 'flow'
            utm_status:
                type: str
                description: Utm status.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Uuid.
            vlan_cos_fwd:
                type: int
                description: Vlan cos fwd.
            vlan_cos_rev:
                type: int
                description: Vlan cos rev.
            vlan_filter:
                type: str
                description: Vlan filter.
            voip_profile:
                type: str
                description: Voip profile.
            vpntunnel:
                type: str
                description: Vpntunnel.
            waf_profile:
                type: str
                description: Waf profile.
            wanopt:
                type: str
                description: Wanopt.
                choices:
                    - 'disable'
                    - 'enable'
            wanopt_detection:
                type: str
                description: Wanopt detection.
                choices:
                    - 'active'
                    - 'passive'
                    - 'off'
            wanopt_passive_opt:
                type: str
                description: Wanopt passive opt.
                choices:
                    - 'default'
                    - 'transparent'
                    - 'non-transparent'
            wanopt_peer:
                type: str
                description: Wanopt peer.
            wanopt_profile:
                type: str
                description: Wanopt profile.
            wccp:
                type: str
                description: Wccp.
                choices:
                    - 'disable'
                    - 'enable'
            web_auth_cookie:
                type: str
                description: Web auth cookie.
                choices:
                    - 'disable'
                    - 'enable'
            webcache:
                type: str
                description: Webcache.
                choices:
                    - 'disable'
                    - 'enable'
            webcache_https:
                type: str
                description: Webcache https.
                choices:
                    - 'disable'
                    - 'ssl-server'
                    - 'any'
                    - 'enable'
            webfilter_profile:
                type: str
                description: Webfilter profile.
            webproxy_forward_server:
                type: str
                description: Webproxy forward server.
            webproxy_profile:
                type: str
                description: Webproxy profile.
            wsso:
                type: str
                description: Wsso.
                choices:
                    - 'disable'
                    - 'enable'
            fsso_groups:
                type: raw
                description: (list or str) Fsso groups.
            match_vip_only:
                type: str
                description: Match vip only.
                choices:
                    - 'disable'
                    - 'enable'
            np_accelation:
                type: str
                description: Np accelation.
                choices:
                    - 'disable'
                    - 'enable'
            best_route:
                type: str
                description: Best route.
                choices:
                    - 'disable'
                    - 'enable'
            decrypted_traffic_mirror:
                type: str
                description: Decrypted traffic mirror.
            geoip_match:
                type: str
                description: Geoip match.
                choices:
                    - 'physical-location'
                    - 'registered-location'
            internet_service_name:
                type: raw
                description: (list or str) Internet service name.
            internet_service_src_name:
                type: raw
                description: (list or str) Internet service src name.
            poolname6:
                type: raw
                description: (list or str) Poolname6.
            src_vendor_mac:
                type: raw
                description: (list or str) Src vendor mac.
            vendor_mac:
                type: raw
                description: (list or str) Vendor mac.
            file_filter_profile:
                type: str
                description: File filter profile.
            cgn_eif:
                type: str
                description: Enable/Disable CGN endpoint independent filtering.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_eim:
                type: str
                description: Enable/Disable CGN endpoint independent mapping
                choices:
                    - 'disable'
                    - 'enable'
            cgn_log_server_grp:
                type: raw
                description: (list or str) NP log server group name
            cgn_resource_quota:
                type: int
                description: Resource quota
            cgn_session_quota:
                type: int
                description: Session quota
            policy_offload:
                type: str
                description: Enable/Disable hardware session setup for CGNAT.
                choices:
                    - 'disable'
                    - 'enable'
            dynamic_shaping:
                type: str
                description: Enable/disable dynamic RADIUS defined traffic shaping.
                choices:
                    - 'disable'
                    - 'enable'
            passive_wan_health_measurement:
                type: str
                description: Enable/disable passive WAN health measurement.
                choices:
                    - 'disable'
                    - 'enable'
            videofilter_profile:
                type: str
                description: Name of an existing VideoFilter profile.
            ztna_ems_tag:
                type: raw
                description: (list or str) Source ztna-ems-tag names.
            ztna_geo_tag:
                type: raw
                description: (list or str) Source ztna-geo-tag names.
            ztna_status:
                type: str
                description: Enable/disable zero trust access.
                choices:
                    - 'disable'
                    - 'enable'
            access_proxy:
                type: raw
                description: (list) Access proxy.
            dlp_profile:
                type: str
                description: Name of an existing DLP profile.
            dynamic_bypass:
                type: str
                description: Dynamic bypass.
                choices:
                    - 'disable'
                    - 'enable'
            fec:
                type: str
                description: Enable/disable Forward Error Correction on traffic matching this policy on a FEC device.
                choices:
                    - 'disable'
                    - 'enable'
            force_proxy:
                type: str
                description: Force proxy.
                choices:
                    - 'disable'
                    - 'enable'
            http_tunnel_auth:
                type: str
                description: Http tunnel auth.
                choices:
                    - 'disable'
                    - 'enable'
            ia_profile:
                type: raw
                description: (list) Ia profile.
            isolator_server:
                type: raw
                description: (list) Isolator server.
            log_http_transaction:
                type: str
                description: Log http transaction.
                choices:
                    - 'disable'
                    - 'enable'
                    - 'all'
                    - 'utm'
            max_session_per_user:
                type: int
                description: Max session per user.
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
            pass_through:
                type: str
                description: Pass through.
                choices:
                    - 'disable'
                    - 'enable'
            pfcp_profile:
                type: str
                description: PFCP profile.
            policy_expiry:
                type: str
                description: Enable/disable policy expiry.
                choices:
                    - 'disable'
                    - 'enable'
            policy_expiry_date:
                type: str
                description: Policy expiry date
            reverse_cache:
                type: str
                description: Reverse cache.
                choices:
                    - 'disable'
                    - 'enable'
            sctp_filter_profile:
                type: str
                description: Name of an existing SCTP filter profile.
            sgt:
                type: raw
                description: (list) Security group tags.
            sgt_check:
                type: str
                description: Enable/disable security group tags
                choices:
                    - 'disable'
                    - 'enable'
            tcp_timeout_pid:
                type: raw
                description: (list) TCP timeout profile ID
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
            udp_timeout_pid:
                type: raw
                description: (list) UDP timeout profile ID
            ztna_tags_match_logic:
                type: str
                description: Ztna tags match logic.
                choices:
                    - 'or'
                    - 'and'
            uuid_idx:
                type: int
                description: Uuid idx.
            device_ownership:
                type: str
                description: Device ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ssh_policy_check:
                type: str
                description: Ssh policy check.
                choices:
                    - 'disable'
                    - 'enable'
            extended_log:
                type: str
                description: Extended log.
                choices:
                    - 'disable'
                    - 'enable'
            diffserv_copy:
                type: str
                description: Enable to copy packets DiffServ values from sessions original direction to its reply direction.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr6_negate:
                type: str
                description: When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6:
                type: str
                description: Enable/disable use of IPv6 Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_custom:
                type: raw
                description: (list) Custom IPv6 Internet Service name.
            internet_service6_custom_group:
                type: raw
                description: (list) Custom Internet Service6 group name.
            internet_service6_group:
                type: raw
                description: (list) Internet Service group name.
            internet_service6_name:
                type: raw
                description: (list) IPv6 Internet Service name.
            internet_service6_negate:
                type: str
                description: When enabled internet-service6 specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src:
                type: str
                description: Enable/disable use of IPv6 Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet_service6_src_custom:
                type: raw
                description: (list) Custom IPv6 Internet Service source name.
            internet_service6_src_custom_group:
                type: raw
                description: (list) Custom Internet Service6 source group name.
            internet_service6_src_group:
                type: raw
                description: (list) Internet Service6 source group name.
            internet_service6_src_name:
                type: raw
                description: (list) IPv6 Internet Service source name.
            internet_service6_src_negate:
                type: str
                description: When enabled internet-service6-src specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            network_service_dynamic:
                type: raw
                description: (list) Dynamic Network Service name.
            network_service_src_dynamic:
                type: raw
                description: (list) Dynamic Network Service source name.
            reputation_direction6:
                type: str
                description: Direction of the initial traffic for IPv6 reputation to take effect.
                choices:
                    - 'source'
                    - 'destination'
            reputation_minimum6:
                type: int
                description: IPv6 Minimum Reputation to take action.
            srcaddr6_negate:
                type: str
                description: When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            _policy_block:
                type: int
                description: Assigned policy block.
            isolator_profile:
                type: raw
                description: (list) Isolator profile.
            policy_expiry_date_utc:
                type: str
                description: Policy expiry date and time, in epoch format.
            ztna_device_ownership:
                type: str
                description: Enable/disable zero trust device ownership.
                choices:
                    - 'disable'
                    - 'enable'
            ztna_policy_redirect:
                type: str
                description: Redirect ZTNA traffic to matching Access-Proxy proxy-policy.
                choices:
                    - 'disable'
                    - 'enable'
            ip_version_type:
                type: str
                description: IP version of the policy.
            ips_voip_filter:
                type: str
                description: Name of an existing VoIP
            policy_behaviour_type:
                type: str
                description: Behaviour of the policy.
            pcp_inbound:
                type: str
                description: Enable/disable PCP inbound DNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp_outbound:
                type: str
                description: Enable/disable PCP outbound SNAT.
                choices:
                    - 'disable'
                    - 'enable'
            pcp_poolname:
                type: raw
                description: (list) PCP pool names.
            ztna_ems_tag_secondary:
                type: raw
                description: (list) Source ztna-ems-tag-secondary names.
            casb_profile:
                type: str
                description: Name of an existing CASB profile.
            implicit_proxy_detection:
                type: str
                description: Implicit proxy detection.
                choices:
                    - 'disable'
                    - 'enable'
            virtual_patch_profile:
                type: str
                description: Name of an existing virtual-patch profile.
            detect_https_in_http_request:
                type: str
                description: Detect https in http request.
                choices:
                    - 'disable'
                    - 'enable'
            diameter_filter_profile:
                type: str
                description: Name of an existing Diameter filter profile.
            redirect_profile:
                type: raw
                description: (list) Redirect profile.
            port_preserve:
                type: str
                description: Enable/disable preservation of the original source port from source NAT if it has not been used.
                choices:
                    - 'disable'
                    - 'enable'
            cgn_sw_eif_ctrl:
                type: str
                description: Enable/disable software endpoint independent filtering control.
                choices:
                    - 'disable'
                    - 'enable'
            eif_check:
                type: str
                description: Enable/Disable check endpoint-independent-filtering pinhole.
                choices:
                    - 'disable'
                    - 'enable'
            eif_learn:
                type: str
                description: Enable/Disable learning of end-point-independent filtering pinhole.
                choices:
                    - 'disable'
                    - 'enable'
            radius_ip_auth_bypass:
                type: str
                description: Enable IP authentication bypass.
                choices:
                    - 'disable'
                    - 'enable'
            url_risk:
                type: raw
                description: (list) Url risk.
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
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager, check_galaxy_version, check_parameter_bypass
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import get_module_arg_spec


def main():
    urls_list = [
        '/pm/config/global/pkg/{pkg}/global/footer/policy'
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
                'np-accelation': {'v_range': [['6.2.1', '6.4.15']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'best-route': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'decrypted-traffic-mirror': {'v_range': [['6.4.0', '']], 'type': 'str'},
                'geoip-match': {'v_range': [['6.4.0', '']], 'choices': ['physical-location', 'registered-location'], 'type': 'str'},
                'internet-service-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'poolname6': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'src-vendor-mac': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'vendor-mac': {'v_range': [['6.4.0', '']], 'type': 'raw'},
                'file-filter-profile': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'cgn-eif': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-eim': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-log-server-grp': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'raw'},
                'cgn-resource-quota': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'cgn-session-quota': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'type': 'int'},
                'policy-offload': {'v_range': [['6.2.7', '6.2.13'], ['6.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                'device-ownership': {'v_range': [['7.0.5', '7.0.13'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ssh-policy-check': {'v_range': [['7.0.5', '7.0.13'], ['7.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'extended-log': {'v_range': [['7.0.11', '7.0.13'], ['7.2.5', '7.2.8'], ['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
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
                'port-preserve': {'v_range': [['7.4.3', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'cgn-sw-eif-ctrl': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eif-check': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'eif-learn': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'radius-ip-auth-bypass': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-risk': {'v_range': [['7.4.4', '7.4.5']], 'type': 'raw'}
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
                           supports_check_mode=True)

    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('full crud', module_arg_spec, urls_list, module_primary_key, url_params,
                       module, connection, top_level_schema_name='data')
    fmgr.validate_parameters(params_validation_blob)
    fmgr.process_crud()

    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
