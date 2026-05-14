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
module: fmgr_fmupdate_service
short_description: Enable/disable services provided by the built-in FortiGuard.
version_added: "2.0.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_service:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            avips:
                type: str
                description:
                    - Enable/disable the built-in FortiGuard to provide FortiGuard antivirus and IPS updates
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_antispam:
                aliases: ['query-antispam']
                type: str
                description:
                    - Enable/disable antispam service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_antivirus:
                aliases: ['query-antivirus']
                type: str
                description:
                    - Enable/disable antivirus query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_filequery:
                aliases: ['query-filequery']
                type: str
                description:
                    - Enable/disable file query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_geoip:
                aliases: ['query-geoip']
                type: str
                description:
                    - Enable/disable geoip service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_outbreak_prevention:
                aliases: ['query-outbreak-prevention']
                type: str
                description:
                    - Enable/disable  outbreak prevention query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_webfilter:
                aliases: ['query-webfilter']
                type: str
                description:
                    - Enable/disable Web Filter service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            webfilter_https_traversal:
                aliases: ['webfilter-https-traversal']
                type: str
                description:
                    - Enable/disable Web Filter HTTPS traversal
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_iot:
                aliases: ['query-iot']
                type: str
                description:
                    - Enable/disable file query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_iot_collection:
                aliases: ['query-iot-collection']
                type: str
                description:
                    - Enable/disable IoT Collection Query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_iot_vulnerability:
                aliases: ['query-iot-vulnerability']
                type: str
                description:
                    - Enable/disable IoT Vulnerability Query service
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
            query_ioc:
                aliases: ['query-ioc']
                type: str
                description:
                    - Enable/disable the built-in FortiGuard to provide IoC query
                    - disable - Disable setting.
                    - enable - Enable setting.
                choices: ['disable', 'enable']
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Enable/disable services provided by the built-in FortiGuard.
      fortinet.fortimanager.fmgr_fmupdate_service:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_service:
          # avips: <value in [disable, enable]>
          # query_antispam: <value in [disable, enable]>
          # query_antivirus: <value in [disable, enable]>
          # query_filequery: <value in [disable, enable]>
          # query_geoip: <value in [disable, enable]>
          # query_outbreak_prevention: <value in [disable, enable]>
          # query_webfilter: <value in [disable, enable]>
          # webfilter_https_traversal: <value in [disable, enable]>
          # query_iot: <value in [disable, enable]>
          # query_iot_collection: <value in [disable, enable]>
          # query_iot_vulnerability: <value in [disable, enable]>
          # query_ioc: <value in [disable, enable]>
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
        '/cli/global/fmupdate/service'
    ]
    module_arg_spec = {
        'fmupdate_service': {
            'type': 'dict', 'v_range': [['6.0.0', '']],
            'options': {
                'avips': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-antispam': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-antivirus': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-filequery': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-geoip': {'v_range': [['6.0.0', '6.4.1']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-outbreak-prevention': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-webfilter': {'choices': ['disable', 'enable'], 'type': 'str'},
                'webfilter-https-traversal': {'choices': ['disable', 'enable'], 'type': 'str'},
                'query-iot': {'v_range': [['6.4.6', '6.4.15'], ['7.0.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-iot-collection': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-iot-vulnerability': {'v_range': [['7.4.1', '']], 'choices': ['disable', 'enable'], 'type': 'str'},
                'query-ioc': {'v_range': [['7.6.0', '']], 'choices': ['disable', 'enable'], 'type': 'str'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_service'),
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
