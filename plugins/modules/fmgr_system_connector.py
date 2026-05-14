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
module: fmgr_system_connector
short_description: Configure connector.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    system_connector:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            fsso_refresh_interval:
                aliases: ['fsso-refresh-interval']
                type: int
                description: FSSO refresh interval
            fsso_sess_timeout:
                aliases: ['fsso-sess-timeout']
                type: int
                description: FSSO session timeout
            px_refresh_interval:
                aliases: ['px-refresh-interval']
                type: int
                description: PxGrid refresh interval
            px_svr_timeout:
                aliases: ['px-svr-timeout']
                type: int
                description: PxGrid server timeout
            conn_refresh_interval:
                aliases: ['conn-refresh-interval']
                type: int
                description: Connector refresh interval
            cloud_orchest_refresh_interval:
                aliases: ['cloud-orchest-refresh-interval']
                type: int
                description: Cloud Orchestration refresh interval
            faznotify_msg_queue_max:
                aliases: ['faznotify-msg-queue-max']
                type: int
                description: Faznotify max queued message per connector
            faznotify_msg_timeout:
                aliases: ['faznotify-msg-timeout']
                type: int
                description: Faznotify message timeout
            conn_ssl_protocol:
                aliases: ['conn-ssl-protocol']
                type: str
                description:
                    - set the lowest SSL protocol version for connector.
                    - follow-global-ssl-protocol - Follow system.
                    - sslv3 - set SSLv3 as the lowest version.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                    - tlsv1.
                choices: ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2',
                          'tlsv1.3']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure connector.
      fortinet.fortimanager.fmgr_system_connector:
        # workspace_locking_adom: <global or your adom name>
        system_connector:
          # fsso_refresh_interval: <integer>
          # fsso_sess_timeout: <integer>
          # px_refresh_interval: <integer>
          # px_svr_timeout: <integer>
          # conn_refresh_interval: <integer>
          # cloud_orchest_refresh_interval: <integer>
          # faznotify_msg_queue_max: <integer>
          # faznotify_msg_timeout: <integer>
          # conn_ssl_protocol: <value in [follow-global-ssl-protocol, sslv3, tlsv1.0, ...]>
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
        '/cli/global/system/connector'
    ]
    module_arg_spec = {
        'system_connector': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'fsso-refresh-interval': {'type': 'int'},
                'fsso-sess-timeout': {'type': 'int'},
                'px-refresh-interval': {'v_range': [['6.0.0', '7.0.1']], 'type': 'int'},
                'px-svr-timeout': {'type': 'int'},
                'conn-refresh-interval': {'v_range': [['7.0.2', '']], 'type': 'int'},
                'cloud-orchest-refresh-interval': {'v_range': [['7.4.0', '']], 'type': 'int'},
                'faznotify-msg-queue-max': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'faznotify-msg-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'},
                'conn-ssl-protocol': {
                    'v_range': [['7.4.4', '7.4.10'], ['7.6.2', '']],
                    'choices': ['follow-global-ssl-protocol', 'sslv3', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'],
                    'type': 'str'
                }
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'system_connector'),
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
