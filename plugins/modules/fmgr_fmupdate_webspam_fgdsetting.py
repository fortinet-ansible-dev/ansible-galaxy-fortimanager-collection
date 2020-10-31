#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2020 Fortinet, Inc.
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
module: fmgr_fmupdate_webspam_fgdsetting
short_description: Configure the FortiGuard run parameters.
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
    fmupdate_webspam_fgdsetting:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            as-cache:
                type: int
                default: 300
                description: 'Antispam service maximum memory usage in megabytes (Maximum = Physical memory-1024, 0: no limit, default = 300).'
            as-log:
                type: str
                default: 'nospam'
                description:
                 - 'Antispam log setting (default = nospam).'
                 - 'disable - Disable spam log.'
                 - 'nospam - Log non-spam events.'
                 - 'all - Log all spam lookups.'
                choices:
                    - 'disable'
                    - 'nospam'
                    - 'all'
            as-preload:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable preloading antispam database to memory (default = disable).'
                 - 'disable - Disable antispam database preload.'
                 - 'enable - Enable antispam database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            av-cache:
                type: int
                default: 300
                description: 'Antivirus service maximum memory usage, in megabytes (100 - 500, default = 300).'
            av-log:
                type: str
                default: 'novirus'
                description:
                 - 'Antivirus log setting (default = novirus).'
                 - 'disable - Disable virus log.'
                 - 'novirus - Log non-virus events.'
                 - 'all - Log all virus lookups.'
                choices:
                    - 'disable'
                    - 'novirus'
                    - 'all'
            av-preload:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable preloading antivirus database to memory (default = disable).'
                 - 'disable - Disable antivirus database preload.'
                 - 'enable - Enable antivirus database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            av2-cache:
                type: int
                default: 800
                description: 'Antispam service maximum memory usage in megabytes (Maximum = Physical memory-1024, 0: no limit, default = 800).'
            av2-log:
                type: str
                default: 'noav2'
                description:
                 - 'Outbreak prevention log setting (default = noav2).'
                 - 'disable - Disable av2 log.'
                 - 'noav2 - Log non-av2 events.'
                 - 'all - Log all av2 lookups.'
                choices:
                    - 'disable'
                    - 'noav2'
                    - 'all'
            av2-preload:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable preloading outbreak prevention database to memory (default = disable).'
                 - 'disable - Disable outbreak prevention database preload.'
                 - 'enable - Enable outbreak prevention database preload.'
                choices:
                    - 'disable'
                    - 'enable'
            eventlog-query:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable record query to event-log besides fgd-log (default = disable).'
                 - 'disable - Record query to event-log besides fgd-log.'
                 - 'enable - Do not log to event-log.'
                choices:
                    - 'disable'
                    - 'enable'
            fgd-pull-interval:
                type: int
                default: 10
                description: 'Fgd pull interval setting, in minutes (1 - 1440, default = 10).'
            fq-cache:
                type: int
                default: 300
                description: 'File query service maximum memory usage, in megabytes (100 - 500, default = 300).'
            fq-log:
                type: str
                default: 'nofilequery'
                description:
                 - 'File query log setting (default = nofilequery).'
                 - 'disable - Disable file query log.'
                 - 'nofilequery - Log non-file query events.'
                 - 'all - Log all file query events.'
                choices:
                    - 'disable'
                    - 'nofilequery'
                    - 'all'
            fq-preload:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable preloading file query database to memory (default = disable).'
                 - 'disable - Disable file query db preload.'
                 - 'enable - Enable file query db preload.'
                choices:
                    - 'disable'
                    - 'enable'
            linkd-log:
                type: str
                default: 'debug'
                description:
                 - 'Linkd log setting (default = debug).'
                 - 'emergency - The unit is unusable.'
                 - 'alert - Immediate action is required'
                 - 'critical - Functionality is affected.'
                 - 'error - Functionality is probably affected.'
                 - 'warn - Functionality might be affected.'
                 - 'notice - Information about normal events.'
                 - 'info - General information.'
                 - 'debug - Debug information.'
                 - 'disable - Linkd logging is disabled.'
                choices:
                    - 'emergency'
                    - 'alert'
                    - 'critical'
                    - 'error'
                    - 'warn'
                    - 'notice'
                    - 'info'
                    - 'debug'
                    - 'disable'
            max-client-worker:
                type: int
                default: 0
                description: 'max worker for tcp client connection (0~16: 0 means use cpu number up to 4).'
            max-log-quota:
                type: int
                default: 6144
                description: 'Maximum log quota setting, in megabytes (100 - 20480, default = 6144).'
            max-unrated-site:
                type: int
                default: 500
                description: 'Maximum number of unrated site in memory, in kilobytes(10 - 5120, default = 500).'
            restrict-as1-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(1) database version (character limit = 127).'
            restrict-as2-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(2) database version (character limit = 127).'
            restrict-as4-dbver:
                type: str
                description: 'Restrict system update to indicated antispam(4) database version (character limit = 127).'
            restrict-av-dbver:
                type: str
                description: 'Restrict system update to indicated antivirus database version (character limit = 127).'
            restrict-av2-dbver:
                type: str
                description: 'Restrict system update to indicated outbreak prevention database version (character limit = 127).'
            restrict-fq-dbver:
                type: str
                description: 'Restrict system update to indicated file query database version (character limit = 127).'
            restrict-wf-dbver:
                type: str
                description: 'Restrict system update to indicated web filter database version (character limit = 127).'
            server-override:
                description: no description
                type: dict
                required: false
                suboptions:
                    servlist:
                        description: no description
                        type: list
                        suboptions:
                            id:
                                type: int
                                default: 0
                                description: 'Override server ID (1 - 10).'
                            ip:
                                type: str
                                default: '0.0.0.0'
                                description: 'IPv4 address of the override server.'
                            ip6:
                                type: str
                                default: '::'
                                description: 'IPv6 address of the override server.'
                            port:
                                type: int
                                default: 443
                                description: 'Port number to use when contacting FortiGuard (1 - 65535, default = 443).'
                            service-type:
                                description: no description
                                type: list
                                choices:
                                 - fgd
                                 - fgc
                                 - fsa
                    status:
                        type: str
                        default: 'disable'
                        description:
                         - 'Override status.'
                         - 'disable - Disable setting.'
                         - 'enable - Enable setting.'
                        choices:
                            - 'disable'
                            - 'enable'
            stat-log-interval:
                type: int
                default: 60
                description: 'Statistic log interval setting, in minutes (1 - 1440, default = 60).'
            stat-sync-interval:
                type: int
                default: 60
                description: 'Synchronization interval for statistic of unrated site in minutes (1 - 60, default = 60).'
            update-interval:
                type: int
                default: 6
                description: 'FortiGuard database update wait time if not enough delta files, in hours (2 - 24, default = 6).'
            update-log:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable update log setting (default = enable).'
                 - 'disable - Disable update log.'
                 - 'enable - Enable update log.'
                choices:
                    - 'disable'
                    - 'enable'
            wf-cache:
                type: int
                default: 0
                description: 'Web filter service maximum memory usage, in megabytes (maximum = Physical memory-1024, 0 = no limit, default = 600).'
            wf-dn-cache-expire-time:
                type: int
                default: 30
                description: 'Web filter DN cache expire time, in minutes (1 - 1440, 0 = never, default = 30).'
            wf-dn-cache-max-number:
                type: int
                default: 10000
                description: 'Maximum number of Web filter DN cache (0 = disable, default = 10000).'
            wf-log:
                type: str
                default: 'nourl'
                description:
                 - 'Web filter log setting (default = nour1)'
                 - 'disable - Disable URL log.'
                 - 'nourl - Log non-URL events.'
                 - 'all - Log all URL lookups.'
                choices:
                    - 'disable'
                    - 'nourl'
                    - 'all'
            wf-preload:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable preloading the web filter database into memory (default = disable).'
                 - 'disable - Disable web filter database preload.'
                 - 'enable - Enable web filter database preload.'
                choices:
                    - 'disable'
                    - 'enable'

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
    - name: Configure the FortiGuard run parameters.
      fmgr_fmupdate_webspam_fgdsetting:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         fmupdate_webspam_fgdsetting:
            as-cache: <value of integer>
            as-log: <value in [disable, nospam, all]>
            as-preload: <value in [disable, enable]>
            av-cache: <value of integer>
            av-log: <value in [disable, novirus, all]>
            av-preload: <value in [disable, enable]>
            av2-cache: <value of integer>
            av2-log: <value in [disable, noav2, all]>
            av2-preload: <value in [disable, enable]>
            eventlog-query: <value in [disable, enable]>
            fgd-pull-interval: <value of integer>
            fq-cache: <value of integer>
            fq-log: <value in [disable, nofilequery, all]>
            fq-preload: <value in [disable, enable]>
            linkd-log: <value in [emergency, alert, critical, ...]>
            max-client-worker: <value of integer>
            max-log-quota: <value of integer>
            max-unrated-site: <value of integer>
            restrict-as1-dbver: <value of string>
            restrict-as2-dbver: <value of string>
            restrict-as4-dbver: <value of string>
            restrict-av-dbver: <value of string>
            restrict-av2-dbver: <value of string>
            restrict-fq-dbver: <value of string>
            restrict-wf-dbver: <value of string>
            server-override:
               servlist:
                 -
                     id: <value of integer>
                     ip: <value of string>
                     ip6: <value of string>
                     port: <value of integer>
                     service-type:
                       - fgd
                       - fgc
                       - fsa
               status: <value in [disable, enable]>
            stat-log-interval: <value of integer>
            stat-sync-interval: <value of integer>
            update-interval: <value of integer>
            update-log: <value in [disable, enable]>
            wf-cache: <value of integer>
            wf-dn-cache-expire-time: <value of integer>
            wf-dn-cache-max-number: <value of integer>
            wf-log: <value in [disable, nourl, all]>
            wf-preload: <value in [disable, enable]>

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
        '/cli/global/fmupdate/web-spam/fgd-setting'
    ]

    perobject_jrpc_urls = [
        '/cli/global/fmupdate/web-spam/fgd-setting/{fgd-setting}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
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
        'fmupdate_webspam_fgdsetting': {
            'required': False,
            'type': 'dict',
            'options': {
                'as-cache': {
                    'required': False,
                    'type': 'int'
                },
                'as-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'nospam',
                        'all'
                    ],
                    'type': 'str'
                },
                'as-preload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av-cache': {
                    'required': False,
                    'type': 'int'
                },
                'av-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'novirus',
                        'all'
                    ],
                    'type': 'str'
                },
                'av-preload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'av2-cache': {
                    'required': False,
                    'type': 'int'
                },
                'av2-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'noav2',
                        'all'
                    ],
                    'type': 'str'
                },
                'av2-preload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'eventlog-query': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'fgd-pull-interval': {
                    'required': False,
                    'type': 'int'
                },
                'fq-cache': {
                    'required': False,
                    'type': 'int'
                },
                'fq-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'nofilequery',
                        'all'
                    ],
                    'type': 'str'
                },
                'fq-preload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'linkd-log': {
                    'required': False,
                    'choices': [
                        'emergency',
                        'alert',
                        'critical',
                        'error',
                        'warn',
                        'notice',
                        'info',
                        'debug',
                        'disable'
                    ],
                    'type': 'str'
                },
                'max-client-worker': {
                    'required': False,
                    'type': 'int'
                },
                'max-log-quota': {
                    'required': False,
                    'type': 'int'
                },
                'max-unrated-site': {
                    'required': False,
                    'type': 'int'
                },
                'restrict-as1-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-as2-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-as4-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-av-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-av2-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-fq-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'restrict-wf-dbver': {
                    'required': False,
                    'type': 'str'
                },
                'server-override': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'servlist': {
                            'required': False,
                            'type': 'list',
                            'options': {
                                'id': {
                                    'required': False,
                                    'type': 'int'
                                },
                                'ip': {
                                    'required': False,
                                    'type': 'str'
                                },
                                'ip6': {
                                    'required': False,
                                    'type': 'str'
                                },
                                'port': {
                                    'required': False,
                                    'type': 'int'
                                },
                                'service-type': {
                                    'required': False,
                                    'type': 'list',
                                    'choices': [
                                        'fgd',
                                        'fgc',
                                        'fsa'
                                    ]
                                }
                            }
                        },
                        'status': {
                            'required': False,
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'stat-log-interval': {
                    'required': False,
                    'type': 'int'
                },
                'stat-sync-interval': {
                    'required': False,
                    'type': 'int'
                },
                'update-interval': {
                    'required': False,
                    'type': 'int'
                },
                'update-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'wf-cache': {
                    'required': False,
                    'type': 'int'
                },
                'wf-dn-cache-expire-time': {
                    'required': False,
                    'type': 'int'
                },
                'wf-dn-cache-max-number': {
                    'required': False,
                    'type': 'int'
                },
                'wf-log': {
                    'required': False,
                    'choices': [
                        'disable',
                        'nourl',
                        'all'
                    ],
                    'type': 'str'
                },
                'wf-preload': {
                    'required': False,
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fmupdate_webspam_fgdsetting'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd()
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
