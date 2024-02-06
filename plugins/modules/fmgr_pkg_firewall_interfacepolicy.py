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
module: fmgr_pkg_firewall_interfacepolicy
short_description: Configure IPv4 interface policies.
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
    pkg:
        description: The parameter (pkg) in requested url.
        type: str
        required: true
    pkg_firewall_interfacepolicy:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            address-type:
                type: str
                description: Deprecated, please rename it to address_type. Address-Type.
                choices:
                    - 'ipv4'
                    - 'ipv6'
            application-list:
                type: str
                description: Deprecated, please rename it to application_list. Application list name.
            application-list-status:
                type: str
                description: Deprecated, please rename it to application_list_status. Enable/disable application control.
                choices:
                    - 'disable'
                    - 'enable'
            av-profile:
                type: str
                description: Deprecated, please rename it to av_profile. Antivirus profile.
            av-profile-status:
                type: str
                description: Deprecated, please rename it to av_profile_status. Enable/disable antivirus.
                choices:
                    - 'disable'
                    - 'enable'
            comments:
                type: str
                description: Comments.
            dlp-sensor:
                type: str
                description: Deprecated, please rename it to dlp_sensor. DLP sensor name.
            dlp-sensor-status:
                type: str
                description: Deprecated, please rename it to dlp_sensor_status. Enable/disable DLP.
                choices:
                    - 'disable'
                    - 'enable'
            dsri:
                type: str
                description: Enable/disable DSRI.
                choices:
                    - 'disable'
                    - 'enable'
            dstaddr:
                type: raw
                description: (list or str) Address object to limit traffic monitoring to network traffic sent to the specified address or range.
            interface:
                type: str
                description: Monitored interface name from available interfaces.
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. IPS sensor name.
            ips-sensor-status:
                type: str
                description: Deprecated, please rename it to ips_sensor_status. Enable/disable IPS.
                choices:
                    - 'disable'
                    - 'enable'
            label:
                type: str
                description: Label.
            logtraffic:
                type: str
                description: Logging type to be used in this policy
                choices:
                    - 'disable'
                    - 'all'
                    - 'utm'
            policyid:
                type: int
                description: Policy ID.
                required: true
            scan-botnet-connections:
                type: str
                description: Deprecated, please rename it to scan_botnet_connections. Enable/disable scanning for connections to Botnet servers.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'
            service:
                type: raw
                description: (list or str) Service object from available options.
            spamfilter-profile:
                type: str
                description: Deprecated, please rename it to spamfilter_profile. Antispam profile.
            spamfilter-profile-status:
                type: str
                description: Deprecated, please rename it to spamfilter_profile_status. Enable/disable antispam.
                choices:
                    - 'disable'
                    - 'enable'
            srcaddr:
                type: raw
                description: (list or str) Address object to limit traffic monitoring to network traffic sent from the specified address or range.
            status:
                type: str
                description: Enable/disable this policy.
                choices:
                    - 'disable'
                    - 'enable'
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile. Web filter profile.
            webfilter-profile-status:
                type: str
                description: Deprecated, please rename it to webfilter_profile_status. Enable/disable web filtering.
                choices:
                    - 'disable'
                    - 'enable'
            emailfilter-profile:
                type: str
                description: Deprecated, please rename it to emailfilter_profile. Email filter profile.
            emailfilter-profile-status:
                type: str
                description: Deprecated, please rename it to emailfilter_profile_status. Enable/disable email filter.
                choices:
                    - 'disable'
                    - 'enable'
            uuid:
                type: str
                description: Universally Unique Identifier
            casi-profile:
                type: str
                description: Deprecated, please rename it to casi_profile. CASI profile name.
            casi-profile-status:
                type: str
                description: Deprecated, please rename it to casi_profile_status. Enable/disable CASI.
                choices:
                    - 'disable'
                    - 'enable'
            dlp-profile:
                type: str
                description: Deprecated, please rename it to dlp_profile. DLP profile name.
            dlp-profile-status:
                type: str
                description: Deprecated, please rename it to dlp_profile_status. Enable/disable DLP.
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
    - name: Configure IPv4 interface policies.
      fortinet.fortimanager.fmgr_pkg_firewall_interfacepolicy:
        bypass_validation: false
        adom: ansible
        pkg: ansible # package name
        state: present
        pkg_firewall_interfacepolicy:
          address-type: ipv4 # <value in [ipv4, ipv6]>
          comments: "ansible-comment"
          interface: sslvpn_tun_intf
          policyid: 1
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
    - name: Retrieve all the IPv4 interface policies
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "pkg_firewall_interfacepolicy"
          params:
            adom: "ansible"
            pkg: "ansible" # package name
            interface-policy: "your_value"
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
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/pkg/{pkg}/firewall/interface-policy/{interface-policy}'
    ]

    url_params = ['adom', 'pkg']
    module_primary_key = 'policyid'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'pkg': {'required': True, 'type': 'str'},
        'pkg_firewall_interfacepolicy': {
            'type': 'dict',
            'v_range': [['6.0.0', '7.2.2']],
            'options': {
                'address-type': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['ipv4', 'ipv6'], 'type': 'str'},
                'application-list': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'application-list-status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'av-profile': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'av-profile-status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'comments': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'dlp-sensor': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'dlp-sensor-status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dsri': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dstaddr': {'v_range': [['6.0.0', '7.2.2']], 'type': 'raw'},
                'interface': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'ips-sensor': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'ips-sensor-status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'label': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'logtraffic': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'all', 'utm'], 'type': 'str'},
                'policyid': {'v_range': [['6.0.0', '7.2.2']], 'required': True, 'type': 'int'},
                'scan-botnet-connections': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'block', 'monitor'], 'type': 'str'},
                'service': {'v_range': [['6.0.0', '7.2.2']], 'type': 'raw'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'spamfilter-profile-status': {'v_range': [['6.0.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'srcaddr': {'v_range': [['6.0.0', '7.2.2']], 'type': 'raw'},
                'status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-profile': {'v_range': [['6.0.0', '7.2.2']], 'type': 'str'},
                'webfilter-profile-status': {'v_range': [['6.0.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['6.2.0', '7.2.2']], 'type': 'str'},
                'emailfilter-profile-status': {'v_range': [['6.2.0', '7.2.2']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'uuid': {'v_range': [['6.2.1', '7.2.0']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.12']], 'type': 'str'},
                'casi-profile-status': {'v_range': [['6.2.0', '6.2.12']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'dlp-profile': {'v_range': [['7.2.0', '7.2.1']], 'type': 'str'},
                'dlp-profile-status': {'v_range': [['7.2.0', '7.2.1']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'pkg_firewall_interfacepolicy'),
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
