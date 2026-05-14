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
module: fmgr_wanopt_profile_mapi
short_description: Enable/disable MAPI email WAN Optimization and configure MAPI WAN Optimization features.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    revision_note:
        description: The change note that can be specified when an object is created or updated.
        type: str
    adom:
        description: The parameter (adom) in requested url.
        type: str
        required: true
    profile:
        description: The parameter (profile) in requested url.
        type: str
        required: true
    wanopt_profile_mapi:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            byte_caching:
                aliases: ['byte-caching']
                type: str
                description: Enable/disable byte-caching for HTTP.
                choices: ['disable', 'enable']
            log_traffic:
                aliases: ['log-traffic']
                type: str
                description: Enable/disable logging.
                choices: ['disable', 'enable']
            port:
                type: raw
                description: (list) Single port number or port number range for MAPI.
            secure_tunnel:
                aliases: ['secure-tunnel']
                type: str
                description: Enable/disable securing the WAN Opt tunnel using SSL.
                choices: ['disable', 'enable']
            status:
                type: str
                description: Enable/disable HTTP WAN Optimization.
                choices: ['disable', 'enable']
            tunnel_sharing:
                aliases: ['tunnel-sharing']
                type: str
                description: Tunnel sharing mode for aggressive/non-aggressive and/or interactive/non-interactive protocols.
                choices: ['private', 'shared', 'express-shared']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Enable/disable MAPI email WAN Optimization and configure MAPI WAN Optimization features.
      fortinet.fortimanager.fmgr_wanopt_profile_mapi:
        # workspace_locking_adom: <global or your adom name>
        adom: <your own value>
        profile: <your own value>
        wanopt_profile_mapi:
          # byte_caching: <value in [disable, enable]>
          # log_traffic: <value in [disable, enable]>
          # port: <list or integer>
          # secure_tunnel: <value in [disable, enable]>
          # status: <value in [disable, enable]>
          # tunnel_sharing: <value in [private, shared, express-shared]>
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
        '/pm/config/adom/{adom}/obj/wanopt/profile/{profile}/mapi',
        '/pm/config/global/obj/wanopt/profile/{profile}/mapi'
    ]
    module_arg_spec = {
        'adom': {'required': True, 'type': 'str'},
        'profile': {'required': True, 'type': 'str'},
        'revision_note': {'type': 'str'},
        'wanopt_profile_mapi': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'byte-caching': {'choices': ['disable', 'enable'], 'type': 'str'},
                'log-traffic': {'choices': ['disable', 'enable'], 'type': 'str'},
                'port': {'v_range': [['6.0.0', '7.6.2']], 'type': 'raw'},
                'secure-tunnel': {'choices': ['disable', 'enable'], 'type': 'str'},
                'status': {'choices': ['disable', 'enable'], 'type': 'str'},
                'tunnel-sharing': {'choices': ['private', 'shared', 'express-shared'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'wanopt_profile_mapi'),
                           supports_check_mode=True)
    if not module._socket_path:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    connection = Connection(module._socket_path)
    fmgr = NAPIManager('partial crud', module_arg_spec, urls_list,
                       None, 'data', module, connection)
    fmgr.process_partial_crud()
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
