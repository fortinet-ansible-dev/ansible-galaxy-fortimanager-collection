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
module: fmgr_firewall_profilegroup
short_description: Configure profile groups.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    firewall_profilegroup:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            application-list:
                type: str
                description: Deprecated, please rename it to application_list. Name of an existing Application list.
            av-profile:
                type: str
                description: Deprecated, please rename it to av_profile. Name of an existing Antivirus profile.
            dlp-sensor:
                type: str
                description: Deprecated, please rename it to dlp_sensor. Name of an existing DLP sensor.
            dnsfilter-profile:
                type: str
                description: Deprecated, please rename it to dnsfilter_profile. Name of an existing DNS filter profile.
            icap-profile:
                type: str
                description: Deprecated, please rename it to icap_profile. Name of an existing ICAP profile.
            ips-sensor:
                type: str
                description: Deprecated, please rename it to ips_sensor. Name of an existing IPS sensor.
            mms-profile:
                type: str
                description: Deprecated, please rename it to mms_profile. Name of an existing MMS profile.
            name:
                type: str
                description: Profile group name.
                required: true
            profile-protocol-options:
                type: str
                description: Deprecated, please rename it to profile_protocol_options. Name of an existing Protocol options profile.
            spamfilter-profile:
                type: str
                description: Deprecated, please rename it to spamfilter_profile. Name of an existing Spam filter profile.
            ssh-filter-profile:
                type: str
                description: Deprecated, please rename it to ssh_filter_profile. Name of an existing SSH filter profile.
            ssl-ssh-profile:
                type: str
                description: Deprecated, please rename it to ssl_ssh_profile. Name of an existing SSL SSH profile.
            voip-profile:
                type: str
                description: Deprecated, please rename it to voip_profile. Name of an existing VoIP profile.
            waf-profile:
                type: str
                description: Deprecated, please rename it to waf_profile. Name of an existing Web application firewall profile.
            webfilter-profile:
                type: str
                description: Deprecated, please rename it to webfilter_profile. Name of an existing Web filter profile.
            cifs-profile:
                type: str
                description: Deprecated, please rename it to cifs_profile. Name of an existing CIFS profile.
            emailfilter-profile:
                type: str
                description: Deprecated, please rename it to emailfilter_profile. Name of an existing email filter profile.
            casi-profile:
                type: str
                description: Deprecated, please rename it to casi_profile. CASI profile.
            file-filter-profile:
                type: str
                description: Deprecated, please rename it to file_filter_profile. Name of an existing file-filter profile.
            videofilter-profile:
                type: str
                description: Deprecated, please rename it to videofilter_profile. Name of an existing VideoFilter profile.
            dlp-profile:
                type: str
                description: Deprecated, please rename it to dlp_profile. Name of an existing DLP profile.
            sctp-filter-profile:
                type: str
                description: Deprecated, please rename it to sctp_filter_profile. Name of an existing SCTP filter profile.
            ips-voip-filter:
                type: str
                description: Deprecated, please rename it to ips_voip_filter. Name of an existing VoIP
            casb-profile:
                type: str
                description: Deprecated, please rename it to casb_profile. Name of an existing CASB profile.
            virtual-patch-profile:
                type: str
                description: Deprecated, please rename it to virtual_patch_profile. Name of an existing virtual-patch profile.
            diameter-filter-profile:
                type: str
                description: Deprecated, please rename it to diameter_filter_profile. Name of an existing Diameter filter profile.
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
    - name: Configure profile groups.
      fortinet.fortimanager.fmgr_firewall_profilegroup:
        bypass_validation: false
        adom: ansible
        state: present
        firewall_profilegroup:
          application-list: "default" # need a valid profile name
          name: "ansible-test"

- name: Gathering fortimanager facts
  hosts: fortimanagers
  gather_facts: false
  connection: httpapi
  vars:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false
    ansible_httpapi_port: 443
  tasks:
    - name: Retrieve all the profile groups
      fortinet.fortimanager.fmgr_fact:
        facts:
          selector: "firewall_profilegroup"
          params:
            adom: "ansible"
            profile-group: "your_value"
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
        '/pm/config/adom/{adom}/obj/firewall/profile-group',
        '/pm/config/global/obj/firewall/profile-group'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/firewall/profile-group/{profile-group}',
        '/pm/config/global/obj/firewall/profile-group/{profile-group}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'firewall_profilegroup': {
            'type': 'dict',
            'v_range': [['6.0.0', '']],
            'options': {
                'application-list': {'type': 'str'},
                'av-profile': {'type': 'str'},
                'dlp-sensor': {'type': 'str'},
                'dnsfilter-profile': {'type': 'str'},
                'icap-profile': {'type': 'str'},
                'ips-sensor': {'type': 'str'},
                'mms-profile': {'type': 'str'},
                'name': {'required': True, 'type': 'str'},
                'profile-protocol-options': {'type': 'str'},
                'spamfilter-profile': {'v_range': [['6.0.0', '7.2.1']], 'type': 'str'},
                'ssh-filter-profile': {'type': 'str'},
                'ssl-ssh-profile': {'type': 'str'},
                'voip-profile': {'type': 'str'},
                'waf-profile': {'type': 'str'},
                'webfilter-profile': {'type': 'str'},
                'cifs-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'emailfilter-profile': {'v_range': [['6.2.0', '']], 'type': 'str'},
                'casi-profile': {'v_range': [['6.2.0', '6.2.12']], 'type': 'str'},
                'file-filter-profile': {'v_range': [['6.4.1', '']], 'type': 'str'},
                'videofilter-profile': {'v_range': [['7.0.0', '']], 'type': 'str'},
                'dlp-profile': {'v_range': [['7.2.0', '']], 'type': 'str'},
                'sctp-filter-profile': {'v_range': [['7.0.1', '']], 'type': 'str'},
                'ips-voip-filter': {'v_range': [['7.2.3', '']], 'type': 'str'},
                'casb-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'virtual-patch-profile': {'v_range': [['7.4.1', '']], 'type': 'str'},
                'diameter-filter-profile': {'v_range': [['7.4.2', '']], 'type': 'str'}
            }

        }
    }

    module_option_spec = get_module_arg_spec('full crud')
    module_arg_spec.update(module_option_spec)
    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_profilegroup'),
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
