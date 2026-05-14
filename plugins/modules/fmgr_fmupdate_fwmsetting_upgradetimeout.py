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
module: fmgr_fmupdate_fwmsetting_upgradetimeout
short_description: Configure the timeout value of image upgrade process.
version_added: "2.2.0"
extends_documentation_fragment:
    - fortinet.fortimanager.general
    - fortinet.fortimanager.general.partial_crud
options:
    fmupdate_fwmsetting_upgradetimeout:
        description: The top level parameters set.
        required: false
        type: dict
        suboptions:
            check_status_timeout:
                aliases: ['check-status-timeout']
                type: int
                description: Timeout for checking status after tunnnel is up.
            ctrl_check_status_timeout:
                aliases: ['ctrl-check-status-timeout']
                type: int
                description: Timeout for checking fap/fsw/fext status after request upgrade.
            ctrl_put_image_by_fds_timeout:
                aliases: ['ctrl-put-image-by-fds-timeout']
                type: int
                description: Timeout for waiting device get fap/fsw/fext image from fortiguard.
            ha_sync_timeout:
                aliases: ['ha-sync-timeout']
                type: int
                description: Timeout for waiting HA sync.
            license_check_timeout:
                aliases: ['license-check-timeout']
                type: int
                description: Timeout for waiting fortigate check license.
            prepare_image_timeout:
                aliases: ['prepare-image-timeout']
                type: int
                description: Timeout for preparing image.
            put_image_by_fds_timeout:
                aliases: ['put-image-by-fds-timeout']
                type: int
                description: Timeout for waiting device get image from fortiguard.
            put_image_timeout:
                aliases: ['put-image-timeout']
                type: int
                description: Timeout for waiting send image over tunnel.
            reboot_of_fsck_timeout:
                aliases: ['reboot-of-fsck-timeout']
                type: int
                description: Timeout for waiting fortigate reboot.
            reboot_of_upgrade_timeout:
                aliases: ['reboot-of-upgrade-timeout']
                type: int
                description: Timeout for waiting fortigate reboot after image upgrade.
            retrieve_timeout:
                aliases: ['retrieve-timeout']
                type: int
                description: Timeout for waiting retrieve.
            rpc_timeout:
                aliases: ['rpc-timeout']
                type: int
                description: Timeout for waiting fortigate rpc response.
            total_timeout:
                aliases: ['total-timeout']
                type: int
                description: Timeout for the whole fortigate upgrade
            health_check_timeout:
                aliases: ['health-check-timeout']
                type: int
                description: Timeout for waiting retrieve.
'''

EXAMPLES = '''
- name: Example playbook (generated based on argument schema)
  hosts: fortimanagers
  connection: httpapi
  gather_facts: false
  tasks:
    - name: Configure the timeout value of image upgrade process.
      fortinet.fortimanager.fmgr_fmupdate_fwmsetting_upgradetimeout:
        # workspace_locking_adom: <global or your adom name>
        fmupdate_fwmsetting_upgradetimeout:
          # check_status_timeout: <integer>
          # ctrl_check_status_timeout: <integer>
          # ctrl_put_image_by_fds_timeout: <integer>
          # ha_sync_timeout: <integer>
          # license_check_timeout: <integer>
          # prepare_image_timeout: <integer>
          # put_image_by_fds_timeout: <integer>
          # put_image_timeout: <integer>
          # reboot_of_fsck_timeout: <integer>
          # reboot_of_upgrade_timeout: <integer>
          # retrieve_timeout: <integer>
          # rpc_timeout: <integer>
          # total_timeout: <integer>
          # health_check_timeout: <integer>
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
        '/cli/global/fmupdate/fwm-setting/upgrade-timeout'
    ]
    module_arg_spec = {
        'fmupdate_fwmsetting_upgradetimeout': {
            'type': 'dict', 'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']],
            'options': {
                'check-status-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-check-status-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'ctrl-put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'ha-sync-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'license-check-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'prepare-image-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'put-image-by-fds-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'put-image-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-fsck-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'reboot-of-upgrade-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'retrieve-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'rpc-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'total-timeout': {'v_range': [['7.0.5', '7.0.16'], ['7.2.2', '']], 'type': 'int'},
                'health-check-timeout': {'v_range': [['7.4.2', '']], 'type': 'int'}
            }
        }
    }

    module_option_spec = get_module_arg_spec('partial crud')
    module_arg_spec.update(module_option_spec)
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_fwmsetting_upgradetimeout'),
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
