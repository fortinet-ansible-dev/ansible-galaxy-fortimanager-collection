#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_securityconsole_install_package
short_description: no description
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    bypass_validation:
        description: |
          only set to True when module schema diffs with FortiManager API structure,
           module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: |
          the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    securityconsole_install_package:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            adom:
                type: str
                description: no description
            adom_rev_comments:
                type: str
                description: no description
            adom_rev_name:
                type: str
                description: no description
            dev_rev_comments:
                type: str
                description: no description
            flags:
                description: description
                type: list
                choices:
                 - none
                 - cp_all_objs
                 - preview
                 - generate_rev
                 - copy_assigned_pkg
                 - unassign
                 - ifpolicy_only
                 - no_ifpolicy
                 - objs_only
                 - auto_lock_ws
                 - check_pkg_st
                 - copy_only
            pkg:
                type: str
                description: no description
            scope:
                description: description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description

'''

EXAMPLES = '''
 - hosts: fortimanager00
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Copy and install a policy package to devices.
      fmgr_securityconsole_install_package:
         bypass_validation: False
         securityconsole_install_package:
            adom: ansible
            adom_rev_comments: ansible-comment
            adom_rev_name: ansible-test
            dev_rev_comments: ansible-comment
            flags:
              - none
              - cp_all_objs
              - preview
              - generate_rev
              - copy_assigned_pkg
              - unassign
              - ifpolicy_only
              - no_ifpolicy
              - objs_only
              - auto_lock_ws
              - check_pkg_st
              - copy_only
            pkg: ansible
            scope:
              -
                  name: ansible-test
                  vdom: root
 - name: INSTALL PREVIEW - POLICY PACKAGE
   hosts: fmg
   connection: httpapi
   collections: fortinet.fortimanager
   vars:
     adom: demo
     ppkg: ppkg_hubs
     device: fgt_00_1
   tasks:
     - name: Install for policy package {{ adom }}/{{ ppkg }} [preview mode]
       fmgr_securityconsole_install_package:
         securityconsole_install_package:
           adom: "{{ adom }}"
           flags:
              - preview
           pkg: "{{ ppkg }}"
           scope:
             - name: "{{ device }}"
               vdom: root
       register: r
     - name: Poll the task
       fmgr_fact:
         facts:
           selector: 'task_task'
           params:
             task: '{{ r.meta.response_data.task }}'
       register: taskinfo
       until: taskinfo.meta.response_data.percent == 100
       retries: 30
       delay: 5
     - name: Trigger the preview report generation for policy package {{ adom }}/{{ ppkg }}
       fmgr_securityconsole_install_preview:
         securityconsole_install_preview:
           adom: "{{ adom }}"
           device: "{{ device }}"
           flags:
             - json
           vdoms: root
       register: r
     - name: Poll the task
       fmgr_fact:
         facts:
           selector: 'task_task'
           params:
             task: '{{ r.meta.response_data.task }}'
       register: taskinfo
       until: taskinfo.meta.response_data.percent == 100
       retries: 30
       delay: 5
     - name: Get the preview report for policy package {{ adom }}/{{ ppkg }}
       fmgr_securityconsole_preview_result:
         securityconsole_preview_result:
            adom: "{{ adom }}"
            device: "{{ device }}"
       register: r
     - name: Cancel install task for policy package {{ adom }}/{{ ppkg }}
       fmgr_securityconsole_package_cancel_install:
         securityconsole_package_cancel_install:
           adom: "{{ adom }}"
     - name: Show preview report
       debug:
         msg: "{{ r }}"

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/securityconsole/install/package'
    ]

    perobject_jrpc_urls = [
        '/securityconsole/install/package/{package}'
    ]

    url_params = []
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'securityconsole_install_package': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.1': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.4.0': True,
                '6.4.2': True,
                '6.4.5': True,
                '7.0.0': True,
                '7.2.0': True
            },
            'options': {
                'adom': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'adom_rev_comments': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'adom_rev_name': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'dev_rev_comments': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'flags': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'none',
                        'cp_all_objs',
                        'preview',
                        'generate_rev',
                        'copy_assigned_pkg',
                        'unassign',
                        'ifpolicy_only',
                        'no_ifpolicy',
                        'objs_only',
                        'auto_lock_ws',
                        'check_pkg_st',
                        'copy_only'
                    ]
                },
                'pkg': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'scope': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vdom': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'securityconsole_install_package'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, None, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_exec(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
