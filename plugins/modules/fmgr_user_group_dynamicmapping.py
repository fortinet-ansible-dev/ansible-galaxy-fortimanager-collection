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
module: fmgr_user_group_dynamicmapping
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
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
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
    group:
        description: the parameter (group) in requested url
        type: str
        required: true
    user_group_dynamicmapping:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            _scope:
                description: description
                type: list
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            auth-concurrent-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auth-concurrent-value:
                type: int
                description: no description
            authtimeout:
                type: int
                description: no description
            company:
                type: str
                description: no description
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            email:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            expire:
                type: int
                description: no description
            expire-type:
                type: str
                description: no description
                choices:
                    - 'immediately'
                    - 'first-successful-login'
            group-type:
                type: str
                description: no description
                choices:
                    - 'firewall'
                    - 'directory-service'
                    - 'fsso-service'
                    - 'guest'
                    - 'rsso'
            guest:
                description: description
                type: list
                suboptions:
                    comment:
                        type: str
                        description: no description
                    company:
                        type: str
                        description: no description
                    email:
                        type: str
                        description: no description
                    expiration:
                        type: str
                        description: no description
                    group:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    mobile-phone:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    password:
                        description: description
                        type: str
                    sponsor:
                        type: str
                        description: no description
                    user-id:
                        type: str
                        description: no description
            http-digest-realm:
                type: str
                description: no description
            id:
                type: int
                description: no description
            ldap-memberof:
                type: str
                description: no description
            logic-type:
                type: str
                description: no description
                choices:
                    - 'or'
                    - 'and'
            match:
                description: description
                type: list
                suboptions:
                    _gui_meta:
                        type: str
                        description: no description
                    group-name:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    server-name:
                        type: str
                        description: no description
            max-accounts:
                type: int
                description: no description
            member:
                description: description
                type: str
            mobile-phone:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            multiple-guest-add:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            password:
                type: str
                description: no description
                choices:
                    - 'auto-generate'
                    - 'specify'
                    - 'disable'
            redir-url:
                type: str
                description: no description
            sms-custom-server:
                type: str
                description: no description
            sms-server:
                type: str
                description: no description
                choices:
                    - 'fortiguard'
                    - 'custom'
            sponsor:
                type: str
                description: no description
                choices:
                    - 'optional'
                    - 'mandatory'
                    - 'disabled'
            sslvpn-bookmarks-group:
                description: description
                type: str
            sslvpn-cache-cleaner:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-client-check:
                description: description
                type: list
                choices:
                 - forticlient
                 - forticlient-av
                 - forticlient-fw
                 - 3rdAV
                 - 3rdFW
            sslvpn-ftp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-http:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-os-check:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-os-check-list:
                description: no description
                type: dict
                required: false
                suboptions:
                    action:
                        type: str
                        description: no description
                        choices:
                            - 'allow'
                            - 'check-up-to-date'
                            - 'deny'
                    latest-patch-level:
                        type: str
                        description: no description
                    name:
                        type: str
                        description: no description
                    tolerance:
                        type: int
                        description: no description
            sslvpn-portal:
                description: description
                type: str
            sslvpn-portal-heading:
                type: str
                description: no description
            sslvpn-rdp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-samba:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-split-tunneling:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-ssh:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-telnet:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-tunnel:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-tunnel-endip:
                type: str
                description: no description
            sslvpn-tunnel-ip-mode:
                type: str
                description: no description
                choices:
                    - 'range'
                    - 'usrgrp'
            sslvpn-tunnel-startip:
                type: str
                description: no description
            sslvpn-virtual-desktop:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-vnc:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sslvpn-webapp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            sso-attribute-value:
                type: str
                description: no description
            user-id:
                type: str
                description: no description
                choices:
                    - 'email'
                    - 'auto-generate'
                    - 'specify'
            user-name:
                type: str
                description: no description
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
    - name: no description
      fmgr_user_group_dynamicmapping:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         group: <your own value>
         state: <value in [present, absent]>
         user_group_dynamicmapping:
            _scope:
              -
                  name: <value of string>
                  vdom: <value of string>
            auth-concurrent-override: <value in [disable, enable]>
            auth-concurrent-value: <value of integer>
            authtimeout: <value of integer>
            company: <value in [optional, mandatory, disabled]>
            email: <value in [disable, enable]>
            expire: <value of integer>
            expire-type: <value in [immediately, first-successful-login]>
            group-type: <value in [firewall, directory-service, fsso-service, ...]>
            guest:
              -
                  comment: <value of string>
                  company: <value of string>
                  email: <value of string>
                  expiration: <value of string>
                  group: <value of string>
                  id: <value of integer>
                  mobile-phone: <value of string>
                  name: <value of string>
                  password: <value of string>
                  sponsor: <value of string>
                  user-id: <value of string>
            http-digest-realm: <value of string>
            id: <value of integer>
            ldap-memberof: <value of string>
            logic-type: <value in [or, and]>
            match:
              -
                  _gui_meta: <value of string>
                  group-name: <value of string>
                  id: <value of integer>
                  server-name: <value of string>
            max-accounts: <value of integer>
            member: <value of string>
            mobile-phone: <value in [disable, enable]>
            multiple-guest-add: <value in [disable, enable]>
            password: <value in [auto-generate, specify, disable]>
            redir-url: <value of string>
            sms-custom-server: <value of string>
            sms-server: <value in [fortiguard, custom]>
            sponsor: <value in [optional, mandatory, disabled]>
            sslvpn-bookmarks-group: <value of string>
            sslvpn-cache-cleaner: <value in [disable, enable]>
            sslvpn-client-check:
              - forticlient
              - forticlient-av
              - forticlient-fw
              - 3rdAV
              - 3rdFW
            sslvpn-ftp: <value in [disable, enable]>
            sslvpn-http: <value in [disable, enable]>
            sslvpn-os-check: <value in [disable, enable]>
            sslvpn-os-check-list:
               action: <value in [allow, check-up-to-date, deny]>
               latest-patch-level: <value of string>
               name: <value of string>
               tolerance: <value of integer>
            sslvpn-portal: <value of string>
            sslvpn-portal-heading: <value of string>
            sslvpn-rdp: <value in [disable, enable]>
            sslvpn-samba: <value in [disable, enable]>
            sslvpn-split-tunneling: <value in [disable, enable]>
            sslvpn-ssh: <value in [disable, enable]>
            sslvpn-telnet: <value in [disable, enable]>
            sslvpn-tunnel: <value in [disable, enable]>
            sslvpn-tunnel-endip: <value of string>
            sslvpn-tunnel-ip-mode: <value in [range, usrgrp]>
            sslvpn-tunnel-startip: <value of string>
            sslvpn-virtual-desktop: <value in [disable, enable]>
            sslvpn-vnc: <value in [disable, enable]>
            sslvpn-webapp: <value in [disable, enable]>
            sso-attribute-value: <value of string>
            user-id: <value in [email, auto-generate, specify]>
            user-name: <value in [disable, enable]>

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
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping',
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}',
        '/pm/config/adom/{adom}/obj/user/group/{group}/dynamic_mapping/{dynamic_mapping}'
    ]

    url_params = ['adom', 'group']
    module_primary_key = 'id'
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
        'group': {
            'required': True,
            'type': 'str'
        },
        'user_group_dynamicmapping': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.0': True
            },
            'options': {
                '_scope': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'vdom': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'auth-concurrent-override': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auth-concurrent-value': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'authtimeout': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'company': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'optional',
                        'mandatory',
                        'disabled'
                    ],
                    'type': 'str'
                },
                'email': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'expire': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'expire-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'immediately',
                        'first-successful-login'
                    ],
                    'type': 'str'
                },
                'group-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'firewall',
                        'directory-service',
                        'fsso-service',
                        'guest',
                        'rsso'
                    ],
                    'type': 'str'
                },
                'guest': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        'comment': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'company': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'email': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'expiration': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'group': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'mobile-phone': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'password': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'sponsor': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'user-id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'http-digest-realm': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'id': {
                    'required': True,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'ldap-memberof': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'logic-type': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'or',
                        'and'
                    ],
                    'type': 'str'
                },
                'match': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'options': {
                        '_gui_meta': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'group-name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        },
                        'server-name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'max-accounts': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'int'
                },
                'member': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'mobile-phone': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'multiple-guest-add': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'password': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'auto-generate',
                        'specify',
                        'disable'
                    ],
                    'type': 'str'
                },
                'redir-url': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sms-custom-server': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sms-server': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'fortiguard',
                        'custom'
                    ],
                    'type': 'str'
                },
                'sponsor': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'optional',
                        'mandatory',
                        'disabled'
                    ],
                    'type': 'str'
                },
                'sslvpn-bookmarks-group': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sslvpn-cache-cleaner': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-client-check': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'list',
                    'choices': [
                        'forticlient',
                        'forticlient-av',
                        'forticlient-fw',
                        '3rdAV',
                        '3rdFW'
                    ]
                },
                'sslvpn-ftp': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-http': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-os-check': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-os-check-list': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'choices': [
                                'allow',
                                'check-up-to-date',
                                'deny'
                            ],
                            'type': 'str'
                        },
                        'latest-patch-level': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'str'
                        },
                        'tolerance': {
                            'required': False,
                            'revision': {
                                '7.2.0': True
                            },
                            'type': 'int'
                        }
                    }
                },
                'sslvpn-portal': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sslvpn-portal-heading': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sslvpn-rdp': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-samba': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-split-tunneling': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-ssh': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-telnet': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-tunnel': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-tunnel-endip': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sslvpn-tunnel-ip-mode': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'range',
                        'usrgrp'
                    ],
                    'type': 'str'
                },
                'sslvpn-tunnel-startip': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'sslvpn-virtual-desktop': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-vnc': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sslvpn-webapp': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'sso-attribute-value': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'type': 'str'
                },
                'user-id': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
                    'choices': [
                        'email',
                        'auto-generate',
                        'specify'
                    ],
                    'type': 'str'
                },
                'user-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True
                    },
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'user_group_dynamicmapping'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
