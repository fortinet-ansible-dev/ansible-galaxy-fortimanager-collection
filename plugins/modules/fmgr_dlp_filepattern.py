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
module: fmgr_dlp_filepattern
short_description: Configure file patterns used by DLP blocking.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.10"
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
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock for FortiManager running in workspace mode, the value can be global and others including root
        required: false
        type: str
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: false
        type: int
        default: 300
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    dlp_filepattern:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: 'Optional comments.'
            entries:
                description: no description
                type: list
                suboptions:
                    file-type:
                        type: str
                        description: 'Select a file type.'
                        choices:
                            - 'unknown'
                            - 'ignored'
                            - 'exe'
                            - 'elf'
                            - 'bat'
                            - 'javascript'
                            - 'html'
                            - 'hta'
                            - 'msoffice'
                            - 'gzip'
                            - 'rar'
                            - 'tar'
                            - 'lzh'
                            - 'upx'
                            - 'zip'
                            - 'cab'
                            - 'bzip2'
                            - 'bzip'
                            - 'activemime'
                            - 'mime'
                            - 'hlp'
                            - 'arj'
                            - 'base64'
                            - 'binhex'
                            - 'uue'
                            - 'fsg'
                            - 'aspack'
                            - 'msc'
                            - 'petite'
                            - 'jpeg'
                            - 'gif'
                            - 'tiff'
                            - 'png'
                            - 'bmp'
                            - 'msi'
                            - 'mpeg'
                            - 'mov'
                            - 'mp3'
                            - 'wma'
                            - 'wav'
                            - 'pdf'
                            - 'avi'
                            - 'rm'
                            - 'torrent'
                            - 'hibun'
                            - '7z'
                            - 'xz'
                            - 'msofficex'
                            - 'mach-o'
                            - 'dmg'
                            - '.net'
                            - 'xar'
                            - 'chm'
                            - 'iso'
                            - 'crx'
                            - 'sis'
                            - 'prc'
                            - 'class'
                            - 'jad'
                            - 'cod'
                            - 'flac'
                    filter-type:
                        type: str
                        description: 'Filter by file name pattern or by file type.'
                        choices:
                            - 'pattern'
                            - 'type'
                    pattern:
                        type: str
                        description: 'Add a file name pattern.'
            id:
                type: int
                description: 'ID.'
            name:
                type: str
                description: 'Name of table containing the file pattern list.'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure file patterns used by DLP blocking.
      fmgr_dlp_filepattern:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         dlp_filepattern:
            comment: <value of string>
            entries:
              -
                  file-type: <value in [unknown, ignored, exe, ...]>
                  filter-type: <value in [pattern, type]>
                  pattern: <value of string>
            id: <value of integer>
            name: <value of string>

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
        '/pm/config/adom/{adom}/obj/dlp/filepattern',
        '/pm/config/global/obj/dlp/filepattern'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/dlp/filepattern/{filepattern}',
        '/pm/config/global/obj/dlp/filepattern/{filepattern}'
    ]

    url_params = ['adom']
    module_primary_key = 'id'
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
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
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'dlp_filepattern': {
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
                '7.0.0': True
            },
            'options': {
                'comment': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'entries': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'list',
                    'options': {
                        'file-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'unknown',
                                'ignored',
                                'exe',
                                'elf',
                                'bat',
                                'javascript',
                                'html',
                                'hta',
                                'msoffice',
                                'gzip',
                                'rar',
                                'tar',
                                'lzh',
                                'upx',
                                'zip',
                                'cab',
                                'bzip2',
                                'bzip',
                                'activemime',
                                'mime',
                                'hlp',
                                'arj',
                                'base64',
                                'binhex',
                                'uue',
                                'fsg',
                                'aspack',
                                'msc',
                                'petite',
                                'jpeg',
                                'gif',
                                'tiff',
                                'png',
                                'bmp',
                                'msi',
                                'mpeg',
                                'mov',
                                'mp3',
                                'wma',
                                'wav',
                                'pdf',
                                'avi',
                                'rm',
                                'torrent',
                                'hibun',
                                '7z',
                                'xz',
                                'msofficex',
                                'mach-o',
                                'dmg',
                                '.net',
                                'xar',
                                'chm',
                                'iso',
                                'crx',
                                'sis',
                                'prc',
                                'class',
                                'jad',
                                'cod',
                                'flac'
                            ],
                            'type': 'str'
                        },
                        'filter-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'pattern',
                                'type'
                            ],
                            'type': 'str'
                        },
                        'pattern': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'id': {
                    'required': True,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
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
                        '7.0.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'dlp_filepattern'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
