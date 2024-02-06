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
module: fmgr_pkg_firewall_securitypolicy
short_description: Configure NGFW IPv4/IPv6 application policies.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.1.0"
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_securitypolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            action:
                type: str
                description: Policy action
                choices:
                    - 'deny'
                    - 'accept'
            app-category:
                type: raw
                description: (list or str) Deprecated, please rename it to app_category. Application category ID list.
            app-group:
                type: raw
                description: (list or str) Deprecated, please rename it to app_group. Application group names.
            application:
                type: raw
                description: (list) Application ID list.
            application-list:
                type: str
                description: Deprecated, please rename it to application_list. Name of an existing Application list.
            av-profile:
                type: str
                description: Deprecated, please rename it to av_profile. Name of an existing Antivirus profile.
            cifs-profile:
                type: str
                description: Deprecated, please rename it to cifs_profile. Name of an existing CIFS profile.
            comments:
                type: str
                description: Comment.
            dlp-sensor:
                type: str
                description: Deprecated, please rename it to dlp_sensor. Name of an existing DLP sensor.
            dnsfilter-profile:
                type: str
                description: Deprecated, please rename it to dnsfilter_profile. Name of an existing DNS filter profile.
            dstaddr4:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            dstaddr6:
                type: raw
                description: (list or str) Destination IPv6 address name and address group names.
            dstintf:
                type: raw
                description: (list or str) Outgoing
            emailfilter-profile:
                type: str
                description: Deprecated, please rename it to emailfilter_profile. Name of an existing email filter profile.
            enforce-default-app-port:
                type: str
                description: Deprecated, please rename it to enforce_default_app_port. Enable/disable default application port enforcement for allowed ...
                choices:
                    - 'disable'
                    - 'enable'
            groups:
                type: raw
                description: (list or str) Names of user groups that can authenticate with this policy.
            icap-profile:
                type: str
                description: Deprecated, please rename it to icap_profile. Name of an existing ICAP profile.
            internet-service:
                type: str
                description: Deprecated, please rename it to internet_service. Enable/disable use of Internet Services for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom. Custom Internet Service name.
            internet-service-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_custom_group. Custom Internet Service group name.
            internet-service-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_group. Internet Service group name.
            internet-service-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_id. Internet Service ID.
            internet-service-negate:
                type: str
                description: Deprecated, please rename it to internet_service_negate. When enabled internet-service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src:
                type: str
                description: Deprecated, please rename it to internet_service_src. Enable/disable use of Internet Services in source for this policy.
                choices:
                    - 'disable'
                    - 'enable'
            internet-service-src-custom:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom. Custom Internet Service source name.
            internet-service-src-custom-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_custom_group. Custom Internet Service source group name.
            internet-service-src-group:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_group. Internet Service source group name.
            internet-service-src-id:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_id. Internet Service source ID.
            internet-service-src-negate:
                type: str
                description: Deprecated, please rename it to internet_service_src_negate. When enabled internet-service-src specifies what the service ...
                choices:
                    - 'disable'
                    - 'enable'
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. Name of an existing IPS sensor.
            logtraffic:
                type: str
                description: Enable or disable logging.
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            logtraffic-start:
                type: str
                description: Deprecated, please rename it to logtraffic_start. Record logs when a session starts.
                choices:
                    - 'disable'
                    - 'enable'
            mms-profile:
                type: str
                description: Deprecated, please rename it to mms_profile. Name of an existing MMS profile.
            name:
                type: str
                description: Policy name.
            policyid:
                type: int
                description: Policy ID.
                required: true
            profile-group:
                type: str
                description: Deprecated, please rename it to profile_group. Name of profile group.
            profile-protocol-options:
                type: str
                description: Deprecated, please rename it to profile_protocol_options. Name of an existing Protocol options profile.
            profile-type:
                type: str
                description: Deprecated, please rename it to profile_type. Determine whether the firewall policy allows security profile groups or sing...
                choices:
                    - 'single'
                    - 'group'
            schedule:
                type: str
                description: Schedule name.
            service:
                type: raw
                description: (list or str) Service and service group names.
            service-negate:
                type: str
                description: Deprecated, please rename it to service_negate. When enabled service specifies what the service must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr4:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            srcaddr6:
                type: raw
                description: (list or str) Source IPv6 address name and address group names.
            srcintf:
                type: raw
                description: (list or str) Incoming
            ssh-filter-profile:
                type: str
                description: Deprecated, please rename it to ssh_filter_profile. Name of an existing SSH filter profile.
            ssl-ssh-profile:
                type: str
                description: Deprecated, please rename it to ssl_ssh_profile. Name of an existing SSL SSH profile.
            status:
                type: str
                description: Enable or disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            url-category:
                type: raw
                description: (list or str) Deprecated, please rename it to url_category. URL category ID list.
            users:
                type: raw
                description: (list or str) Names of individual users that can authenticate with this policy.
            utm-status:
                type: str
                description: Deprecated, please rename it to utm_status. Enable security profiles.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            voip-profile:
                type: str
                description: Deprecated, please rename it to voip_profile. Name of an existing VoIP profile.
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile. Name of an existing Web filter profile.
            fsso-groups:
                type: raw
                description: (list or str) Deprecated, please rename it to fsso_groups. Names of FSSO groups.
            global-label:
                type: str
                description: Deprecated, please rename it to global_label. Label for the policy that appears when the GUI is in Global View mode.
            send-deny-packet:
                type: str
                description: Deprecated, please rename it to send_deny_packet. Enable to send a reply when a session is denied or blocked by a firewall...
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Destination IPv4 address name and address group names.
            internet-service-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_name. Internet Service name.
            internet-service-src-name:
                type: raw
                description: (list or str) Deprecated, please rename it to internet_service_src_name. Internet Service source name.
            srcaddr:
                type: raw
                description: (list or str) Source IPv4 address name and address group names.
            dstaddr-negate:
                type: str
                description: Deprecated, please rename it to dstaddr_negate. When enabled dstaddr/dstaddr6 specifies what the destination address must ...
                choices:
                    - 'disable'
                    - 'enable'
            file-filter-profile:
                type: str
                description: Deprecated, please rename it to file_filter_profile. Name of an existing file-filter profile.
            srcaddr-negate:
                type: str
                description: Deprecated, please rename it to srcaddr_negate. When enabled srcaddr/srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            learning-mode:
                type: str
                description: Deprecated, please rename it to learning_mode. Enable to allow everything, but log all of the meaningful data for security...
                choices:
                    - 'disable'
                    - 'enable'
            videofilter-profile:
                type: str
                description: Deprecated, please rename it to videofilter_profile. Name of an existing VideoFilter profile.
            _policy_block:
                type: int
                description: Assigned policy block.
            dlp-profile:
                type: str
                description: Deprecated, please rename it to dlp_profile. Name of an existing DLP profile.
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
            sctp-filter-profile:
                type: str
                description: Deprecated, please rename it to sctp_filter_profile. Name of an existing SCTP filter profile.
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
            casb-profile:
                type: str
                description: Deprecated, please rename it to casb_profile. Name of an existing CASB profile.
            diameter-filter-profile:
                type: str
                description: Deprecated, please rename it to diameter_filter_profile. Name of an existing Diameter filter profile.
            dstaddr6-negate:
                type: str
                description: Deprecated, please rename it to dstaddr6_negate. When enabled dstaddr6 specifies what the destination address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            ips-voip-filter:
                type: str
                description: Deprecated, please rename it to ips_voip_filter. Name of an existing VoIP
            srcaddr6-negate:
                type: str
                description: Deprecated, please rename it to srcaddr6_negate. When enabled srcaddr6 specifies what the source address must NOT be.
                choices:
                    - 'disable'
                    - 'enable'
            virtual-patch-profile:
                type: str
                description: Deprecated, please rename it to virtual_patch_profile. Name of an existing virtual-patch profile.
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
    - name: Configure NGFW IPv4/IPv6 application policies.
      fortinet.fortimanager.fmgr_pkg_firewall_securitypolicy:
        # bypass_validation: false
        workspace_locking_adom: <value in [global, custom adom including root]>
        workspace_locking_timeout: 300
        # rc_succeeded: [0, -2, -3, ...]
        # rc_failed: [-2, -3, ...]
        adom: <your own value>
        pkg: <your own value>
        state: present # <value in [present, absent]>
        pkg_firewall_securitypolicy:
          action: <value in [deny, accept]>
          app_category: <list or string>
          app_group: <list or string>
          application: <list or integer>
          application_list: <string>
          av_profile: <string>
          cifs_profile: <string>
          comments: <string>
          dlp_sensor: <string>
          dnsfilter_profile: <string>
          dstaddr4: <list or string>
          dstaddr6: <list or string>
          dstintf: <list or string>
          emailfilter_profile: <string>
          enforce_default_app_port: <value in [disable, enable]>
          groups: <list or string>
          icap_profile: <string>
          internet_service: <value in [disable, enable]>
          internet_service_custom: <list or string>
          internet_service_custom_group: <list or string>
          internet_service_group: <list or string>
          internet_service_id: <list or string>
          internet_service_negate: <value in [disable, enable]>
          internet_service_src: <value in [disable, enable]>
          internet_service_src_custom: <list or string>
          internet_service_src_custom_group: <list or string>
          internet_service_src_group: <list or string>
          internet_service_src_id: <list or string>
          internet_service_src_negate: <value in [disable, enable]>
          ips_sensor: <string>
          logtraffic: <value in [disable, all, utm]>
          logtraffic_start: <value in [disable, enable]>
          mms_profile: <string>
          name: <string>
          policyid: <integer>
          profile_group: <string>
          profile_protocol_options: <string>
          profile_type: <value in [single, group]>
          schedule: <string>
          service: <list or string>
          service_negate: <value in [disable, enable]>
          srcaddr4: <list or string>
          srcaddr6: <list or string>
          srcintf: <list or string>
          ssh_filter_profile: <string>
          ssl_ssh_profile: <string>
          status: <value in [disable, enable]>
          url_category: <list or string>
          users: <list or string>
          utm_status: <value in [disable, enable]>
          uuid: <string>
          voip_profile: <string>
          webfilter_profile: <string>
          fsso_groups: <list or string>
          global_label: <string>
          send_deny_packet: <value in [disable, enable]>
          dstaddr: <list or string>
          internet_service_name: <list or string>
          internet_service_src_name: <list or string>
          srcaddr: <list or string>
          dstaddr_negate: <value in [disable, enable]>
          file_filter_profile: <string>
          srcaddr_negate: <value in [disable, enable]>
          learning_mode: <value in [disable, enable]>
          videofilter_profile: <string>
          _policy_block: <integer>
          dlp_profile: <string>
          nat46: <value in [disable, enable]>
          nat64: <value in [disable, enable]>
          sctp_filter_profile: <string>
          internet_service6: <value in [disable, enable]>
          internet_service6_custom: <list or string>
          internet_service6_custom_group: <list or string>
          internet_service6_group: <list or string>
          internet_service6_name: <list or string>
          internet_service6_negate: <value in [disable, enable]>
          internet_service6_src: <value in [disable, enable]>
          internet_service6_src_custom: <list or string>
          internet_service6_src_custom_group: <list or string>
          internet_service6_src_group: <list or string>
          internet_service6_src_name: <list or string>
          internet_service6_src_negate: <value in [disable, enable]>
          casb_profile: <string>
          diameter_filter_profile: <string>
          dstaddr6_negate: <value in [disable, enable]>
          ips_voip_filter: <string>
          srcaddr6_negate: <value in [disable, enable]>
          virtual_patch_profile: <string>
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/security-policy/{security-policy}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_firewall_securitypolicy': {
            'type': 'dict',
            'v_range': [['6.2.1', '']],
            'options': {
                'action': {'v_range': [['6.2.1', '']], 'choices': ['deny', 'accept'], 'type': 'str'},
                'app-category': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'app-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'application': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'application-list': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'av-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'cifs-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'comments': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dnsfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'dstaddr4': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'dstaddr6': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'dstintf': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'emailfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'enforce-default-app-port': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'groups': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'icap-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'internet-service': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-custom': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-custom-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-id': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service-src-custom': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-custom-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-group': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-id': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'internet-service-src-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'logtraffic-start': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'mms-profile': {'v_range': [['6.2.1', '7.2.0']], 'type': 'str'},
                'name': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'policyid': {'v_range': [['6.2.1', '']], 'required': True, 'type': 'int'},
                'profile-group': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'profile-protocol-options': {'v_range': [['6.2.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                'profile-type': {'v_range': [['6.2.1', '']], 'choices': ['single', 'group'], 'type': 'str'},
                'schedule': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'service': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'service-negate': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr4': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'srcaddr6': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'srcintf': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'ssh-filter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'ssl-ssh-profile': {'v_range': [['6.2.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                'status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'url-category': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'users': {'v_range': [['6.2.1', '']], 'type': 'raw'},
                'utm-status': {'v_range': [['6.2.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'voip-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.2.1', '']], 'type': 'str'},
                'fsso-groups': {'v_range': [['6.2.2', '']], 'type': 'raw'},
                'global-label': {'v_range': [['6.2.3', '']], 'type': 'str'},
                'send-deny-packet': {'v_range': [['6.2.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service-name': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service-src-name': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'srcaddr': {'v_range': [['6.4.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'dstaddr-negate': {'v_range': [['6.4.2', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'file-filter-profile': {'v_range': [['6.4.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                'srcaddr-negate': {'v_range': [['6.4.2', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'learning-mode': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'videofilter-profile': {'v_range': [['7.0.0', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                '_policy_block': {'v_range': [['7.0.3', '']], 'type': 'int'},
                'dlp-profile': {'v_range': [['7.2.0', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                'nat46': {'v_range': [['7.0.2', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'nat64': {'v_range': [['7.0.2', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'sctp-filter-profile': {'v_range': [['7.0.1', '7.2.2'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'str'},
                'internet-service6': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'internet-service6-custom': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-custom-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-name': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-negate': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'internet-service6-src': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'internet-service6-src-custom': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-custom-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-group': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-name': {'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']], 'type': 'raw'},
                'internet-service6-src-negate': {
                    'v_range': [['7.2.1', '7.2.1'], ['7.2.4', '7.2.4'], ['7.4.2', '']],
                    'choices': ['disable', 'enable'],
                    'type': 'str'
                },
                'casb-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'dstaddr6-negate': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.4.2', '']], 'type': 'str'},
                'srcaddr6-negate': {'v_range': [['7.4.2', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.2', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_securitypolicy'),
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
