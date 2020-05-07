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
module: fmgr_system_global
short_description: Global range attributes.
description:
    - This module is able to configure a FortiManager device by allowing the
      user to [ get set update ] the following apis.
    - /cli/global/system/global
    - Examples include all parameters and values need to be adjusted to data sources before usage.

version_added: "2.10"
author:
    - Frank Shen (@fshen01)
    - Link Zheng (@zhengl)
notes:
    - There are only three top-level parameters where 'method' is always required
      while other two 'params' and 'url_params' can be optional
    - Due to the complexity of fortimanager api schema, the validation is done
      out of Ansible native parameter validation procedure.
    - The syntax of OPTIONS doen not comply with the standard Ansible argument
      specification, but with the structure of fortimanager API schema, we need
      a trivial transformation when we are filling the ansible playbook
options:
    loose_validation:
        description: Do parameter validation in a loose way
        required: False
        type: bool
        default: false
    workspace_locking_adom:
        description: the adom to lock in case FortiManager running in workspace mode
        required: False
        type: string
        choices:
          - global
          - custom adom
    workspace_locking_timeout:
        description: the maximum time in seconds to wait for other user to release the workspace lock
        required: False
        type: integer
        default: 300
    schema_object0:
        methods: [get]
        description: 'Global range attributes.'
        api_categories: [api_tag0]
        api_tag0:
    schema_object1:
        methods: [set, update]
        description: 'Global range attributes.'
        api_categories: [api_tag0]
        api_tag0:
            data:
                admin-lockout-duration:
                    type: int
                    default: 60
                    description: 'Lockout duration(sec) for administration.'
                admin-lockout-threshold:
                    type: int
                    default: 3
                    description: 'Lockout threshold for administration.'
                adom-mode:
                    type: str
                    default: 'normal'
                    description:
                     - 'ADOM mode.'
                     - 'normal - Normal ADOM mode.'
                     - 'advanced - Advanced ADOM mode.'
                    choices:
                        - 'normal'
                        - 'advanced'
                adom-rev-auto-delete:
                    type: str
                    default: 'by-revisions'
                    description:
                     - 'Auto delete features for old ADOM revisions.'
                     - 'disable - Disable auto delete function for ADOM revision.'
                     - 'by-revisions - Auto delete ADOM revisions by maximum number of revisions.'
                     - 'by-days - Auto delete ADOM revisions by maximum days.'
                    choices:
                        - 'disable'
                        - 'by-revisions'
                        - 'by-days'
                adom-rev-max-backup-revisions:
                    type: int
                    default: 5
                    description: 'Maximum number of ADOM revisions to backup.'
                adom-rev-max-days:
                    type: int
                    default: 30
                    description: 'Number of days to keep old ADOM revisions.'
                adom-rev-max-revisions:
                    type: int
                    default: 120
                    description: 'Maximum number of ADOM revisions to keep.'
                adom-select:
                    type: str
                    default: 'enable'
                    description:
                     - 'Enable/disable select ADOM after login.'
                     - 'disable - Disable select ADOM after login.'
                     - 'enable - Enable select ADOM after login.'
                    choices:
                        - 'disable'
                        - 'enable'
                adom-status:
                    type: str
                    default: 'disable'
                    description:
                     - 'ADOM status.'
                     - 'disable - Disable ADOM mode.'
                     - 'enable - Enable ADOM mode.'
                    choices:
                        - 'disable'
                        - 'enable'
                clt-cert-req:
                    type: str
                    default: 'disable'
                    description:
                     - 'Require client certificate for GUI login.'
                     - 'disable - Disable setting.'
                     - 'enable - Require client certificate for GUI login.'
                     - 'optional - Optional client certificate for GUI login.'
                    choices:
                        - 'disable'
                        - 'enable'
                        - 'optional'
                console-output:
                    type: str
                    default: 'standard'
                    description:
                     - 'Console output mode.'
                     - 'standard - Standard output.'
                     - 'more - More page output.'
                    choices:
                        - 'standard'
                        - 'more'
                country-flag:
                    type: str
                    default: 'enable'
                    description:
                     - 'Country flag Status.'
                     - 'disable - Disable country flag icon beside ip address.'
                     - 'enable - Enable country flag icon beside ip address.'
                    choices:
                        - 'disable'
                        - 'enable'
                create-revision:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/disable create revision by default.'
                     - 'disable - Disable create revision by default.'
                     - 'enable - Enable create revision by default.'
                    choices:
                        - 'disable'
                        - 'enable'
                daylightsavetime:
                    type: str
                    default: 'enable'
                    description:
                     - 'Enable/disable daylight saving time.'
                     - 'disable - Disable setting.'
                     - 'enable - Enable setting.'
                    choices:
                        - 'disable'
                        - 'enable'
                default-disk-quota:
                    type: int
                    default: 1000
                    description: 'Default disk quota for registered device (MB).'
                detect-unregistered-log-device:
                    type: str
                    default: 'enable'
                    description:
                     - 'Detect unregistered logging device from log message.'
                     - 'disable - Disable attribute function.'
                     - 'enable - Enable attribute function.'
                    choices:
                        - 'disable'
                        - 'enable'
                device-view-mode:
                    type: str
                    default: 'regular'
                    description:
                     - 'Set devices/groups view mode.'
                     - 'regular - Regular view mode.'
                     - 'tree - Tree view mode.'
                    choices:
                        - 'regular'
                        - 'tree'
                dh-params:
                    type: str
                    default: '2048'
                    description:
                     - 'Minimum size of Diffie-Hellman prime for SSH/HTTPS (bits).'
                     - '1024 - 1024 bits.'
                     - '1536 - 1536 bits.'
                     - '2048 - 2048 bits.'
                     - '3072 - 3072 bits.'
                     - '4096 - 4096 bits.'
                     - '6144 - 6144 bits.'
                     - '8192 - 8192 bits.'
                    choices:
                        - '1024'
                        - '1536'
                        - '2048'
                        - '3072'
                        - '4096'
                        - '6144'
                        - '8192'
                disable-module:
                    -
                        type: str
                        choices:
                            - 'fortiview-noc'
                enc-algorithm:
                    type: str
                    default: 'high'
                    description:
                     - 'SSL communication encryption algorithms.'
                     - 'low - SSL communication using all available encryption algorithms.'
                     - 'medium - SSL communication using high and medium encryption algorithms.'
                     - 'high - SSL communication using high encryption algorithms.'
                    choices:
                        - 'low'
                        - 'medium'
                        - 'high'
                faz-status:
                    type: str
                    default: 'disable'
                    description:
                     - 'FAZ status.'
                     - 'disable - Disable FAZ feature.'
                     - 'enable - Enable FAZ feature.'
                    choices:
                        - 'disable'
                        - 'enable'
                fgfm-local-cert:
                    type: str
                    description: 'set the fgfm local certificate.'
                fgfm-ssl-protocol:
                    type: str
                    default: 'tlsv1.2'
                    description:
                     - 'set the lowest SSL protocols for fgfmsd.'
                     - 'sslv3 - set SSLv3 as the lowest version.'
                     - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                     - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                     - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                    choices:
                        - 'sslv3'
                        - 'tlsv1.0'
                        - 'tlsv1.1'
                        - 'tlsv1.2'
                ha-member-auto-grouping:
                    type: str
                    default: 'enable'
                    description:
                     - 'Enable/disable automatically group HA members feature'
                     - 'disable - Disable automatically grouping HA members feature.'
                     - 'enable - Enable automatically grouping HA members only when group name is unique in your network.'
                    choices:
                        - 'disable'
                        - 'enable'
                hitcount_concurrent:
                    type: int
                    default: 100
                    description: 'The number of FortiGates that FortiManager polls at one time (10 - 500, default = 100).'
                hitcount_interval:
                    type: int
                    default: 300
                    description: 'The interval for getting hit count from managed FortiGate devices, in seconds (60 - 86400, default = 300).'
                hostname:
                    type: str
                    default: 'FMG-VM64'
                    description: 'System hostname.'
                import-ignore-addr-cmt:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable import ignore of address comments.'
                     - 'disable - Disable import ignore of address comments.'
                     - 'enable - Enable import ignore of address comments.'
                    choices:
                        - 'disable'
                        - 'enable'
                language:
                    type: str
                    default: 'english'
                    description:
                     - 'System global language.'
                     - 'english - English'
                     - 'simch - Simplified Chinese'
                     - 'japanese - Japanese'
                     - 'korean - Korean'
                     - 'spanish - Spanish'
                     - 'trach - Traditional Chinese'
                    choices:
                        - 'english'
                        - 'simch'
                        - 'japanese'
                        - 'korean'
                        - 'spanish'
                        - 'trach'
                latitude:
                    type: str
                    description: 'fmg location latitude'
                ldap-cache-timeout:
                    type: int
                    default: 86400
                    description: 'LDAP browser cache timeout (seconds).'
                ldapconntimeout:
                    type: int
                    default: 60000
                    description: 'LDAP connection timeout (msec).'
                lock-preempt:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/disable ADOM lock override.'
                     - 'disable - Disable lock preempt.'
                     - 'enable - Enable lock preempt.'
                    choices:
                        - 'disable'
                        - 'enable'
                log-checksum:
                    type: str
                    default: 'none'
                    description:
                     - 'Record log file hash value, timestamp, and authentication code at transmission or rolling.'
                     - 'none - No record log file checksum.'
                     - 'md5 - Record log files MD5 hash value only.'
                     - 'md5-auth - Record log files MD5 hash value and authentication code.'
                    choices:
                        - 'none'
                        - 'md5'
                        - 'md5-auth'
                log-forward-cache-size:
                    type: int
                    default: 0
                    description: 'Log forwarding disk cache size (GB).'
                longitude:
                    type: str
                    description: 'fmg location longitude'
                max-log-forward:
                    type: int
                    default: 5
                    description: 'Maximum number of log-forward and aggregation settings.'
                max-running-reports:
                    type: int
                    default: 1
                    description: 'Maximum number of reports generating at one time.'
                oftp-ssl-protocol:
                    type: str
                    default: 'tlsv1.2'
                    description:
                     - 'set the lowest SSL protocols for oftpd.'
                     - 'sslv3 - set SSLv3 as the lowest version.'
                     - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                     - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                     - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                    choices:
                        - 'sslv3'
                        - 'tlsv1.0'
                        - 'tlsv1.1'
                        - 'tlsv1.2'
                partial-install:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable partial install (install some objects).'
                     - 'disable - Disable partial install function.'
                     - 'enable - Enable partial install function.'
                    choices:
                        - 'disable'
                        - 'enable'
                partial-install-force:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable partial install when devdb is modified.'
                     - 'disable - Disable partial install when devdb is modified.'
                     - 'enable - Enable partial install when devdb is modified.'
                    choices:
                        - 'disable'
                        - 'enable'
                partial-install-rev:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable auto creating adom revision for partial install.'
                     - 'disable - Disable partial install revision.'
                     - 'enable - Enable partial install revision.'
                    choices:
                        - 'disable'
                        - 'enable'
                perform-improve-by-ha:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable performance improvement by distributing tasks to HA slaves.'
                     - 'disable - Disable performance improvement by HA.'
                     - 'enable - Enable performance improvement by HA.'
                    choices:
                        - 'disable'
                        - 'enable'
                policy-hit-count:
                    type: str
                    default: 'disable'
                    description:
                     - 'show policy hit count.'
                     - 'disable - Disable policy hit count.'
                     - 'enable - Enable policy hit count.'
                    choices:
                        - 'disable'
                        - 'enable'
                policy-object-in-dual-pane:
                    type: str
                    default: 'disable'
                    description:
                     - 'show policies and objects in dual pane.'
                     - 'disable - Disable polices and objects in dual pane.'
                     - 'enable - Enable polices and objects in dual pane.'
                    choices:
                        - 'disable'
                        - 'enable'
                pre-login-banner:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/disable pre-login banner.'
                     - 'disable - Disable pre-login banner.'
                     - 'enable - Enable pre-login banner.'
                    choices:
                        - 'disable'
                        - 'enable'
                pre-login-banner-message:
                    type: str
                    description: 'Pre-login banner message.'
                remoteauthtimeout:
                    type: int
                    default: 10
                    description: 'Remote authentication (RADIUS/LDAP) timeout (sec).'
                search-all-adoms:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/Disable Search all ADOMs for where-used query.'
                     - 'disable - Disable search all ADOMs for where-used queries.'
                     - 'enable - Enable search all ADOMs for where-used queries.'
                    choices:
                        - 'disable'
                        - 'enable'
                ssl-low-encryption:
                    type: str
                    default: 'disable'
                    description:
                     - 'SSL low-grade encryption.'
                     - 'disable - Disable SSL low-grade encryption.'
                     - 'enable - Enable SSL low-grade encryption.'
                    choices:
                        - 'disable'
                        - 'enable'
                ssl-protocol:
                    -
                        type: str
                        choices:
                            - 'tlsv1.2'
                            - 'tlsv1.1'
                            - 'tlsv1.0'
                            - 'sslv3'
                ssl-static-key-ciphers:
                    type: str
                    default: 'enable'
                    description:
                     - 'Enable/disable SSL static key ciphers.'
                     - 'disable - Disable setting.'
                     - 'enable - Enable setting.'
                    choices:
                        - 'disable'
                        - 'enable'
                task-list-size:
                    type: int
                    default: 2000
                    description: 'Maximum number of completed tasks to keep.'
                tftp:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/disable TFTP in `exec restore image` command (disabled by default in FIPS mode)'
                     - 'disable - Disable TFTP'
                     - 'enable - Enable TFTP'
                    choices:
                        - 'disable'
                        - 'enable'
                timezone:
                    type: str
                    default: '04'
                    description:
                     - 'Time zone.'
                     - '00 - (GMT-12:00) Eniwetak, Kwajalein.'
                     - '01 - (GMT-11:00) Midway Island, Samoa.'
                     - '02 - (GMT-10:00) Hawaii.'
                     - '03 - (GMT-9:00) Alaska.'
                     - '04 - (GMT-8:00) Pacific Time (US & Canada).'
                     - '05 - (GMT-7:00) Arizona.'
                     - '06 - (GMT-7:00) Mountain Time (US & Canada).'
                     - '07 - (GMT-6:00) Central America.'
                     - '08 - (GMT-6:00) Central Time (US & Canada).'
                     - '09 - (GMT-6:00) Mexico City.'
                     - '10 - (GMT-6:00) Saskatchewan.'
                     - '11 - (GMT-5:00) Bogota, Lima, Quito.'
                     - '12 - (GMT-5:00) Eastern Time (US & Canada).'
                     - '13 - (GMT-5:00) Indiana (East).'
                     - '14 - (GMT-4:00) Atlantic Time (Canada).'
                     - '15 - (GMT-4:00) La Paz.'
                     - '16 - (GMT-4:00) Santiago.'
                     - '17 - (GMT-3:30) Newfoundland.'
                     - '18 - (GMT-3:00) Brasilia.'
                     - '19 - (GMT-3:00) Buenos Aires, Georgetown.'
                     - '20 - (GMT-3:00) Nuuk (Greenland).'
                     - '21 - (GMT-2:00) Mid-Atlantic.'
                     - '22 - (GMT-1:00) Azores.'
                     - '23 - (GMT-1:00) Cape Verde Is.'
                     - '24 - (GMT) Monrovia.'
                     - '25 - (GMT) Greenwich Mean Time:Dublin, Edinburgh, Lisbon, London.'
                     - '26 - (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna.'
                     - '27 - (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague.'
                     - '28 - (GMT+1:00) Brussels, Copenhagen, Madrid, Paris.'
                     - '29 - (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb.'
                     - '30 - (GMT+1:00) West Central Africa.'
                     - '31 - (GMT+2:00) Athens, Sofia, Vilnius.'
                     - '32 - (GMT+2:00) Bucharest.'
                     - '33 - (GMT+2:00) Cairo.'
                     - '34 - (GMT+2:00) Harare, Pretoria.'
                     - '35 - (GMT+2:00) Helsinki, Riga,Tallinn.'
                     - '36 - (GMT+2:00) Jerusalem.'
                     - '37 - (GMT+3:00) Baghdad.'
                     - '38 - (GMT+3:00) Kuwait, Riyadh.'
                     - '39 - (GMT+3:00) St.Petersburg, Volgograd.'
                     - '40 - (GMT+3:00) Nairobi.'
                     - '41 - (GMT+3:30) Tehran.'
                     - '42 - (GMT+4:00) Abu Dhabi, Muscat.'
                     - '43 - (GMT+4:00) Baku.'
                     - '44 - (GMT+4:30) Kabul.'
                     - '45 - (GMT+5:00) Ekaterinburg.'
                     - '46 - (GMT+5:00) Islamabad, Karachi,Tashkent.'
                     - '47 - (GMT+5:30) Calcutta, Chennai, Mumbai, New Delhi.'
                     - '48 - (GMT+5:45) Kathmandu.'
                     - '49 - (GMT+6:00) Almaty, Novosibirsk.'
                     - '50 - (GMT+6:00) Astana, Dhaka.'
                     - '51 - (GMT+6:00) Sri Jayawardenapura.'
                     - '52 - (GMT+6:30) Rangoon.'
                     - '53 - (GMT+7:00) Bangkok, Hanoi, Jakarta.'
                     - '54 - (GMT+7:00) Krasnoyarsk.'
                     - '55 - (GMT+8:00) Beijing,ChongQing, HongKong,Urumqi.'
                     - '56 - (GMT+8:00) Irkutsk, Ulaanbaatar.'
                     - '57 - (GMT+8:00) Kuala Lumpur, Singapore.'
                     - '58 - (GMT+8:00) Perth.'
                     - '59 - (GMT+8:00) Taipei.'
                     - '60 - (GMT+9:00) Osaka, Sapporo, Tokyo, Seoul.'
                     - '61 - (GMT+9:00) Yakutsk.'
                     - '62 - (GMT+9:30) Adelaide.'
                     - '63 - (GMT+9:30) Darwin.'
                     - '64 - (GMT+10:00) Brisbane.'
                     - '65 - (GMT+10:00) Canberra, Melbourne, Sydney.'
                     - '66 - (GMT+10:00) Guam, Port Moresby.'
                     - '67 - (GMT+10:00) Hobart.'
                     - '68 - (GMT+10:00) Vladivostok.'
                     - '69 - (GMT+11:00) Magadan.'
                     - '70 - (GMT+11:00) Solomon Is., New Caledonia.'
                     - '71 - (GMT+12:00) Auckland, Wellington.'
                     - '72 - (GMT+12:00) Fiji, Kamchatka, Marshall Is.'
                     - '73 - (GMT+13:00) Nukualofa.'
                     - '74 - (GMT-4:30) Caracas.'
                     - '75 - (GMT+1:00) Namibia.'
                     - '76 - (GMT-5:00) Brazil-Acre.'
                     - '77 - (GMT-4:00) Brazil-West.'
                     - '78 - (GMT-3:00) Brazil-East.'
                     - '79 - (GMT-2:00) Brazil-DeNoronha.'
                     - '80 - (GMT+14:00) Kiritimati.'
                     - '81 - (GMT-7:00) Baja California Sur, Chihuahua.'
                     - '82 - (GMT+12:45) Chatham Islands.'
                     - '83 - (GMT+3:00) Minsk.'
                     - '84 - (GMT+13:00) Samoa.'
                     - '85 - (GMT+3:00) Istanbul.'
                     - '86 - (GMT-4:00) Paraguay.'
                     - '87 - (GMT) Casablanca.'
                     - '88 - (GMT+3:00) Moscow.'
                     - '89 - (GMT) Greenwich Mean Time.'
                    choices:
                        - '00'
                        - '01'
                        - '02'
                        - '03'
                        - '04'
                        - '05'
                        - '06'
                        - '07'
                        - '08'
                        - '09'
                        - '10'
                        - '11'
                        - '12'
                        - '13'
                        - '14'
                        - '15'
                        - '16'
                        - '17'
                        - '18'
                        - '19'
                        - '20'
                        - '21'
                        - '22'
                        - '23'
                        - '24'
                        - '25'
                        - '26'
                        - '27'
                        - '28'
                        - '29'
                        - '30'
                        - '31'
                        - '32'
                        - '33'
                        - '34'
                        - '35'
                        - '36'
                        - '37'
                        - '38'
                        - '39'
                        - '40'
                        - '41'
                        - '42'
                        - '43'
                        - '44'
                        - '45'
                        - '46'
                        - '47'
                        - '48'
                        - '49'
                        - '50'
                        - '51'
                        - '52'
                        - '53'
                        - '54'
                        - '55'
                        - '56'
                        - '57'
                        - '58'
                        - '59'
                        - '60'
                        - '61'
                        - '62'
                        - '63'
                        - '64'
                        - '65'
                        - '66'
                        - '67'
                        - '68'
                        - '69'
                        - '70'
                        - '71'
                        - '72'
                        - '73'
                        - '74'
                        - '75'
                        - '76'
                        - '77'
                        - '78'
                        - '79'
                        - '80'
                        - '81'
                        - '82'
                        - '83'
                        - '84'
                        - '85'
                        - '86'
                        - '87'
                        - '88'
                        - '89'
                tunnel-mtu:
                    type: int
                    default: 1500
                    description: 'Maximum transportation unit(68 - 9000).'
                usg:
                    type: str
                    default: 'disable'
                    description:
                     - 'Enable/disable Fortiguard server restriction.'
                     - 'disable - Contact any Fortiguard server'
                     - 'enable - Contact Fortiguard server in USA only'
                    choices:
                        - 'disable'
                        - 'enable'
                vdom-mirror:
                    type: str
                    default: 'disable'
                    description:
                     - 'VDOM mirror.'
                     - 'disable - Disable VDOM mirror function.'
                     - 'enable - Enable VDOM mirror function.'
                    choices:
                        - 'disable'
                        - 'enable'
                webservice-proto:
                    -
                        type: str
                        choices:
                            - 'tlsv1.2'
                            - 'tlsv1.1'
                            - 'tlsv1.0'
                            - 'sslv3'
                            - 'sslv2'
                workflow-max-sessions:
                    type: int
                    default: 500
                    description: 'Maximum number of workflow sessions per ADOM (minimum 100).'
                workspace-mode:
                    type: str
                    default: 'disabled'
                    description:
                     - 'Set workspace mode (ADOM Locking).'
                     - 'disabled - Workspace disabled.'
                     - 'normal - Workspace lock mode.'
                     - 'workflow - Workspace workflow mode.'
                    choices:
                        - 'disabled'
                        - 'normal'
                        - 'workflow'

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

    - name: REQUESTING /CLI/SYSTEM/GLOBAL
      fmgr_system_global:
         loose_validation: False
         workspace_locking_adom: <value in [global, custom adom]>
         workspace_locking_timeout: 300
         method: <value in [set, update]>
         params:
            -
               data:
                  admin-lockout-duration: <value of integer default: 60>
                  admin-lockout-threshold: <value of integer default: 3>
                  adom-mode: <value in [normal, advanced] default: 'normal'>
                  adom-rev-auto-delete: <value in [disable, by-revisions, by-days] default: 'by-revisions'>
                  adom-rev-max-backup-revisions: <value of integer default: 5>
                  adom-rev-max-days: <value of integer default: 30>
                  adom-rev-max-revisions: <value of integer default: 120>
                  adom-select: <value in [disable, enable] default: 'enable'>
                  adom-status: <value in [disable, enable] default: 'disable'>
                  clt-cert-req: <value in [disable, enable, optional] default: 'disable'>
                  console-output: <value in [standard, more] default: 'standard'>
                  country-flag: <value in [disable, enable] default: 'enable'>
                  create-revision: <value in [disable, enable] default: 'disable'>
                  daylightsavetime: <value in [disable, enable] default: 'enable'>
                  default-disk-quota: <value of integer default: 1000>
                  detect-unregistered-log-device: <value in [disable, enable] default: 'enable'>
                  device-view-mode: <value in [regular, tree] default: 'regular'>
                  dh-params: <value in [1024, 1536, 2048, ...] default: '2048'>
                  disable-module:
                    - <value in [fortiview-noc]>
                  enc-algorithm: <value in [low, medium, high] default: 'high'>
                  faz-status: <value in [disable, enable] default: 'disable'>
                  fgfm-local-cert: <value of string>
                  fgfm-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...] default: 'tlsv1.2'>
                  ha-member-auto-grouping: <value in [disable, enable] default: 'enable'>
                  hitcount_concurrent: <value of integer default: 100>
                  hitcount_interval: <value of integer default: 300>
                  hostname: <value of string default: 'FMG-VM64'>
                  import-ignore-addr-cmt: <value in [disable, enable] default: 'disable'>
                  language: <value in [english, simch, japanese, ...] default: 'english'>
                  latitude: <value of string>
                  ldap-cache-timeout: <value of integer default: 86400>
                  ldapconntimeout: <value of integer default: 60000>
                  lock-preempt: <value in [disable, enable] default: 'disable'>
                  log-checksum: <value in [none, md5, md5-auth] default: 'none'>
                  log-forward-cache-size: <value of integer default: 0>
                  longitude: <value of string>
                  max-log-forward: <value of integer default: 5>
                  max-running-reports: <value of integer default: 1>
                  oftp-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...] default: 'tlsv1.2'>
                  partial-install: <value in [disable, enable] default: 'disable'>
                  partial-install-force: <value in [disable, enable] default: 'disable'>
                  partial-install-rev: <value in [disable, enable] default: 'disable'>
                  perform-improve-by-ha: <value in [disable, enable] default: 'disable'>
                  policy-hit-count: <value in [disable, enable] default: 'disable'>
                  policy-object-in-dual-pane: <value in [disable, enable] default: 'disable'>
                  pre-login-banner: <value in [disable, enable] default: 'disable'>
                  pre-login-banner-message: <value of string>
                  remoteauthtimeout: <value of integer default: 10>
                  search-all-adoms: <value in [disable, enable] default: 'disable'>
                  ssl-low-encryption: <value in [disable, enable] default: 'disable'>
                  ssl-protocol:
                    - <value in [tlsv1.2, tlsv1.1, tlsv1.0, ...]>
                  ssl-static-key-ciphers: <value in [disable, enable] default: 'enable'>
                  task-list-size: <value of integer default: 2000>
                  tftp: <value in [disable, enable] default: 'disable'>
                  timezone: <value in [00, 01, 02, ...] default: '04'>
                  tunnel-mtu: <value of integer default: 1500>
                  usg: <value in [disable, enable] default: 'disable'>
                  vdom-mirror: <value in [disable, enable] default: 'disable'>
                  webservice-proto:
                    - <value in [tlsv1.2, tlsv1.1, tlsv1.0, ...]>
                  workflow-max-sessions: <value of integer default: 500>
                  workspace-mode: <value in [disabled, normal, workflow] default: 'disabled'>

'''

RETURN = '''
return_of_api_category_0:
   description: items returned for method:[get]
   returned: always
   suboptions:
      id:
         type: int
      result:
         data:
            admin-lockout-duration:
               type: int
               description: 'Lockout duration(sec) for administration.'
               example: 60
            admin-lockout-threshold:
               type: int
               description: 'Lockout threshold for administration.'
               example: 3
            adom-mode:
               type: str
               description: |
                  'ADOM mode.'
                  'normal - Normal ADOM mode.'
                  'advanced - Advanced ADOM mode.'
               example: 'normal'
            adom-rev-auto-delete:
               type: str
               description: |
                  'Auto delete features for old ADOM revisions.'
                  'disable - Disable auto delete function for ADOM revision.'
                  'by-revisions - Auto delete ADOM revisions by maximum number of revisions.'
                  'by-days - Auto delete ADOM revisions by maximum days.'
               example: 'by-revisions'
            adom-rev-max-backup-revisions:
               type: int
               description: 'Maximum number of ADOM revisions to backup.'
               example: 5
            adom-rev-max-days:
               type: int
               description: 'Number of days to keep old ADOM revisions.'
               example: 30
            adom-rev-max-revisions:
               type: int
               description: 'Maximum number of ADOM revisions to keep.'
               example: 120
            adom-select:
               type: str
               description: |
                  'Enable/disable select ADOM after login.'
                  'disable - Disable select ADOM after login.'
                  'enable - Enable select ADOM after login.'
               example: 'enable'
            adom-status:
               type: str
               description: |
                  'ADOM status.'
                  'disable - Disable ADOM mode.'
                  'enable - Enable ADOM mode.'
               example: 'disable'
            clt-cert-req:
               type: str
               description: |
                  'Require client certificate for GUI login.'
                  'disable - Disable setting.'
                  'enable - Require client certificate for GUI login.'
                  'optional - Optional client certificate for GUI login.'
               example: 'disable'
            console-output:
               type: str
               description: |
                  'Console output mode.'
                  'standard - Standard output.'
                  'more - More page output.'
               example: 'standard'
            country-flag:
               type: str
               description: |
                  'Country flag Status.'
                  'disable - Disable country flag icon beside ip address.'
                  'enable - Enable country flag icon beside ip address.'
               example: 'enable'
            create-revision:
               type: str
               description: |
                  'Enable/disable create revision by default.'
                  'disable - Disable create revision by default.'
                  'enable - Enable create revision by default.'
               example: 'disable'
            daylightsavetime:
               type: str
               description: |
                  'Enable/disable daylight saving time.'
                  'disable - Disable setting.'
                  'enable - Enable setting.'
               example: 'enable'
            default-disk-quota:
               type: int
               description: 'Default disk quota for registered device (MB).'
               example: 1000
            detect-unregistered-log-device:
               type: str
               description: |
                  'Detect unregistered logging device from log message.'
                  'disable - Disable attribute function.'
                  'enable - Enable attribute function.'
               example: 'enable'
            device-view-mode:
               type: str
               description: |
                  'Set devices/groups view mode.'
                  'regular - Regular view mode.'
                  'tree - Tree view mode.'
               example: 'regular'
            dh-params:
               type: str
               description: |
                  'Minimum size of Diffie-Hellman prime for SSH/HTTPS (bits).'
                  '1024 - 1024 bits.'
                  '1536 - 1536 bits.'
                  '2048 - 2048 bits.'
                  '3072 - 3072 bits.'
                  '4096 - 4096 bits.'
                  '6144 - 6144 bits.'
                  '8192 - 8192 bits.'
               example: '2048'
            disable-module:
               type: array
               suboptions:
                  type: str
            enc-algorithm:
               type: str
               description: |
                  'SSL communication encryption algorithms.'
                  'low - SSL communication using all available encryption algorithms.'
                  'medium - SSL communication using high and medium encryption algorithms.'
                  'high - SSL communication using high encryption algorithms.'
               example: 'high'
            faz-status:
               type: str
               description: |
                  'FAZ status.'
                  'disable - Disable FAZ feature.'
                  'enable - Enable FAZ feature.'
               example: 'disable'
            fgfm-local-cert:
               type: str
               description: 'set the fgfm local certificate.'
            fgfm-ssl-protocol:
               type: str
               description: |
                  'set the lowest SSL protocols for fgfmsd.'
                  'sslv3 - set SSLv3 as the lowest version.'
                  'tlsv1.0 - set TLSv1.0 as the lowest version.'
                  'tlsv1.1 - set TLSv1.1 as the lowest version.'
                  'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
               example: 'tlsv1.2'
            ha-member-auto-grouping:
               type: str
               description: |
                  'Enable/disable automatically group HA members feature'
                  'disable - Disable automatically grouping HA members feature.'
                  'enable - Enable automatically grouping HA members only when group name is unique in your network.'
               example: 'enable'
            hitcount_concurrent:
               type: int
               description: 'The number of FortiGates that FortiManager polls at one time (10 - 500, default = 100).'
               example: 100
            hitcount_interval:
               type: int
               description: 'The interval for getting hit count from managed FortiGate devices, in seconds (60 - 86400, default = 300).'
               example: 300
            hostname:
               type: str
               description: 'System hostname.'
               example: 'FMG-VM64'
            import-ignore-addr-cmt:
               type: str
               description: |
                  'Enable/Disable import ignore of address comments.'
                  'disable - Disable import ignore of address comments.'
                  'enable - Enable import ignore of address comments.'
               example: 'disable'
            language:
               type: str
               description: |
                  'System global language.'
                  'english - English'
                  'simch - Simplified Chinese'
                  'japanese - Japanese'
                  'korean - Korean'
                  'spanish - Spanish'
                  'trach - Traditional Chinese'
               example: 'english'
            latitude:
               type: str
               description: 'fmg location latitude'
            ldap-cache-timeout:
               type: int
               description: 'LDAP browser cache timeout (seconds).'
               example: 86400
            ldapconntimeout:
               type: int
               description: 'LDAP connection timeout (msec).'
               example: 60000
            lock-preempt:
               type: str
               description: |
                  'Enable/disable ADOM lock override.'
                  'disable - Disable lock preempt.'
                  'enable - Enable lock preempt.'
               example: 'disable'
            log-checksum:
               type: str
               description: |
                  'Record log file hash value, timestamp, and authentication code at transmission or rolling.'
                  'none - No record log file checksum.'
                  'md5 - Record log files MD5 hash value only.'
                  'md5-auth - Record log files MD5 hash value and authentication code.'
               example: 'none'
            log-forward-cache-size:
               type: int
               description: 'Log forwarding disk cache size (GB).'
               example: 0
            longitude:
               type: str
               description: 'fmg location longitude'
            max-log-forward:
               type: int
               description: 'Maximum number of log-forward and aggregation settings.'
               example: 5
            max-running-reports:
               type: int
               description: 'Maximum number of reports generating at one time.'
               example: 1
            oftp-ssl-protocol:
               type: str
               description: |
                  'set the lowest SSL protocols for oftpd.'
                  'sslv3 - set SSLv3 as the lowest version.'
                  'tlsv1.0 - set TLSv1.0 as the lowest version.'
                  'tlsv1.1 - set TLSv1.1 as the lowest version.'
                  'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
               example: 'tlsv1.2'
            partial-install:
               type: str
               description: |
                  'Enable/Disable partial install (install some objects).'
                  'disable - Disable partial install function.'
                  'enable - Enable partial install function.'
               example: 'disable'
            partial-install-force:
               type: str
               description: |
                  'Enable/Disable partial install when devdb is modified.'
                  'disable - Disable partial install when devdb is modified.'
                  'enable - Enable partial install when devdb is modified.'
               example: 'disable'
            partial-install-rev:
               type: str
               description: |
                  'Enable/Disable auto creating adom revision for partial install.'
                  'disable - Disable partial install revision.'
                  'enable - Enable partial install revision.'
               example: 'disable'
            perform-improve-by-ha:
               type: str
               description: |
                  'Enable/Disable performance improvement by distributing tasks to HA slaves.'
                  'disable - Disable performance improvement by HA.'
                  'enable - Enable performance improvement by HA.'
               example: 'disable'
            policy-hit-count:
               type: str
               description: |
                  'show policy hit count.'
                  'disable - Disable policy hit count.'
                  'enable - Enable policy hit count.'
               example: 'disable'
            policy-object-in-dual-pane:
               type: str
               description: |
                  'show policies and objects in dual pane.'
                  'disable - Disable polices and objects in dual pane.'
                  'enable - Enable polices and objects in dual pane.'
               example: 'disable'
            pre-login-banner:
               type: str
               description: |
                  'Enable/disable pre-login banner.'
                  'disable - Disable pre-login banner.'
                  'enable - Enable pre-login banner.'
               example: 'disable'
            pre-login-banner-message:
               type: str
               description: 'Pre-login banner message.'
            remoteauthtimeout:
               type: int
               description: 'Remote authentication (RADIUS/LDAP) timeout (sec).'
               example: 10
            search-all-adoms:
               type: str
               description: |
                  'Enable/Disable Search all ADOMs for where-used query.'
                  'disable - Disable search all ADOMs for where-used queries.'
                  'enable - Enable search all ADOMs for where-used queries.'
               example: 'disable'
            ssl-low-encryption:
               type: str
               description: |
                  'SSL low-grade encryption.'
                  'disable - Disable SSL low-grade encryption.'
                  'enable - Enable SSL low-grade encryption.'
               example: 'disable'
            ssl-protocol:
               type: array
               suboptions:
                  type: str
            ssl-static-key-ciphers:
               type: str
               description: |
                  'Enable/disable SSL static key ciphers.'
                  'disable - Disable setting.'
                  'enable - Enable setting.'
               example: 'enable'
            task-list-size:
               type: int
               description: 'Maximum number of completed tasks to keep.'
               example: 2000
            tftp:
               type: str
               description: |
                  'Enable/disable TFTP in `exec restore image` command (disabled by default in FIPS mode)'
                  'disable - Disable TFTP'
                  'enable - Enable TFTP'
               example: 'disable'
            timezone:
               type: str
               description: |
                  'Time zone.'
                  '00 - (GMT-12:00) Eniwetak, Kwajalein.'
                  '01 - (GMT-11:00) Midway Island, Samoa.'
                  '02 - (GMT-10:00) Hawaii.'
                  '03 - (GMT-9:00) Alaska.'
                  '04 - (GMT-8:00) Pacific Time (US & Canada).'
                  '05 - (GMT-7:00) Arizona.'
                  '06 - (GMT-7:00) Mountain Time (US & Canada).'
                  '07 - (GMT-6:00) Central America.'
                  '08 - (GMT-6:00) Central Time (US & Canada).'
                  '09 - (GMT-6:00) Mexico City.'
                  '10 - (GMT-6:00) Saskatchewan.'
                  '11 - (GMT-5:00) Bogota, Lima, Quito.'
                  '12 - (GMT-5:00) Eastern Time (US & Canada).'
                  '13 - (GMT-5:00) Indiana (East).'
                  '14 - (GMT-4:00) Atlantic Time (Canada).'
                  '15 - (GMT-4:00) La Paz.'
                  '16 - (GMT-4:00) Santiago.'
                  '17 - (GMT-3:30) Newfoundland.'
                  '18 - (GMT-3:00) Brasilia.'
                  '19 - (GMT-3:00) Buenos Aires, Georgetown.'
                  '20 - (GMT-3:00) Nuuk (Greenland).'
                  '21 - (GMT-2:00) Mid-Atlantic.'
                  '22 - (GMT-1:00) Azores.'
                  '23 - (GMT-1:00) Cape Verde Is.'
                  '24 - (GMT) Monrovia.'
                  '25 - (GMT) Greenwich Mean Time:Dublin, Edinburgh, Lisbon, London.'
                  '26 - (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna.'
                  '27 - (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague.'
                  '28 - (GMT+1:00) Brussels, Copenhagen, Madrid, Paris.'
                  '29 - (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb.'
                  '30 - (GMT+1:00) West Central Africa.'
                  '31 - (GMT+2:00) Athens, Sofia, Vilnius.'
                  '32 - (GMT+2:00) Bucharest.'
                  '33 - (GMT+2:00) Cairo.'
                  '34 - (GMT+2:00) Harare, Pretoria.'
                  '35 - (GMT+2:00) Helsinki, Riga,Tallinn.'
                  '36 - (GMT+2:00) Jerusalem.'
                  '37 - (GMT+3:00) Baghdad.'
                  '38 - (GMT+3:00) Kuwait, Riyadh.'
                  '39 - (GMT+3:00) St.Petersburg, Volgograd.'
                  '40 - (GMT+3:00) Nairobi.'
                  '41 - (GMT+3:30) Tehran.'
                  '42 - (GMT+4:00) Abu Dhabi, Muscat.'
                  '43 - (GMT+4:00) Baku.'
                  '44 - (GMT+4:30) Kabul.'
                  '45 - (GMT+5:00) Ekaterinburg.'
                  '46 - (GMT+5:00) Islamabad, Karachi,Tashkent.'
                  '47 - (GMT+5:30) Calcutta, Chennai, Mumbai, New Delhi.'
                  '48 - (GMT+5:45) Kathmandu.'
                  '49 - (GMT+6:00) Almaty, Novosibirsk.'
                  '50 - (GMT+6:00) Astana, Dhaka.'
                  '51 - (GMT+6:00) Sri Jayawardenapura.'
                  '52 - (GMT+6:30) Rangoon.'
                  '53 - (GMT+7:00) Bangkok, Hanoi, Jakarta.'
                  '54 - (GMT+7:00) Krasnoyarsk.'
                  '55 - (GMT+8:00) Beijing,ChongQing, HongKong,Urumqi.'
                  '56 - (GMT+8:00) Irkutsk, Ulaanbaatar.'
                  '57 - (GMT+8:00) Kuala Lumpur, Singapore.'
                  '58 - (GMT+8:00) Perth.'
                  '59 - (GMT+8:00) Taipei.'
                  '60 - (GMT+9:00) Osaka, Sapporo, Tokyo, Seoul.'
                  '61 - (GMT+9:00) Yakutsk.'
                  '62 - (GMT+9:30) Adelaide.'
                  '63 - (GMT+9:30) Darwin.'
                  '64 - (GMT+10:00) Brisbane.'
                  '65 - (GMT+10:00) Canberra, Melbourne, Sydney.'
                  '66 - (GMT+10:00) Guam, Port Moresby.'
                  '67 - (GMT+10:00) Hobart.'
                  '68 - (GMT+10:00) Vladivostok.'
                  '69 - (GMT+11:00) Magadan.'
                  '70 - (GMT+11:00) Solomon Is., New Caledonia.'
                  '71 - (GMT+12:00) Auckland, Wellington.'
                  '72 - (GMT+12:00) Fiji, Kamchatka, Marshall Is.'
                  '73 - (GMT+13:00) Nukualofa.'
                  '74 - (GMT-4:30) Caracas.'
                  '75 - (GMT+1:00) Namibia.'
                  '76 - (GMT-5:00) Brazil-Acre.'
                  '77 - (GMT-4:00) Brazil-West.'
                  '78 - (GMT-3:00) Brazil-East.'
                  '79 - (GMT-2:00) Brazil-DeNoronha.'
                  '80 - (GMT+14:00) Kiritimati.'
                  '81 - (GMT-7:00) Baja California Sur, Chihuahua.'
                  '82 - (GMT+12:45) Chatham Islands.'
                  '83 - (GMT+3:00) Minsk.'
                  '84 - (GMT+13:00) Samoa.'
                  '85 - (GMT+3:00) Istanbul.'
                  '86 - (GMT-4:00) Paraguay.'
                  '87 - (GMT) Casablanca.'
                  '88 - (GMT+3:00) Moscow.'
                  '89 - (GMT) Greenwich Mean Time.'
               example: '04'
            tunnel-mtu:
               type: int
               description: 'Maximum transportation unit(68 - 9000).'
               example: 1500
            usg:
               type: str
               description: |
                  'Enable/disable Fortiguard server restriction.'
                  'disable - Contact any Fortiguard server'
                  'enable - Contact Fortiguard server in USA only'
               example: 'disable'
            vdom-mirror:
               type: str
               description: |
                  'VDOM mirror.'
                  'disable - Disable VDOM mirror function.'
                  'enable - Enable VDOM mirror function.'
               example: 'disable'
            webservice-proto:
               type: array
               suboptions:
                  type: str
            workflow-max-sessions:
               type: int
               description: 'Maximum number of workflow sessions per ADOM (minimum 100).'
               example: 500
            workspace-mode:
               type: str
               description: |
                  'Set workspace mode (ADOM Locking).'
                  'disabled - Workspace disabled.'
                  'normal - Workspace lock mode.'
                  'workflow - Workspace workflow mode.'
               example: 'disabled'
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/cli/global/system/global'
return_of_api_category_0:
   description: items returned for method:[set, update]
   returned: always
   suboptions:
      id:
         type: int
      result:
         status:
            code:
               type: int
            message:
               type: str
         url:
            type: str
            example: '/cli/global/system/global'

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FAIL_SOCKET_MSG
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import DEFAULT_RESULT_OBJ
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGRCommon
from ansible_collections.fortinet.fortimanager.plugins.module_utils.common import FMGBaseException
from ansible_collections.fortinet.fortimanager.plugins.module_utils.fortimanager import FortiManagerHandler


def main():
    jrpc_urls = [
        '/cli/global/system/global'
    ]

    url_schema = [
    ]

    body_schema = {
        'schema_objects': {
            'object0': [
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ],
            'object1': [
                {
                    'name': 'data',
                    'type': 'dict',
                    'dict': {
                        'admin-lockout-duration': {
                            'type': 'integer',
                            'default': 60,
                            'example': 60
                        },
                        'admin-lockout-threshold': {
                            'type': 'integer',
                            'default': 3,
                            'example': 3
                        },
                        'adom-mode': {
                            'type': 'string',
                            'enum': [
                                'normal',
                                'advanced'
                            ]
                        },
                        'adom-rev-auto-delete': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'by-revisions',
                                'by-days'
                            ]
                        },
                        'adom-rev-max-backup-revisions': {
                            'type': 'integer',
                            'default': 5,
                            'example': 5
                        },
                        'adom-rev-max-days': {
                            'type': 'integer',
                            'default': 30,
                            'example': 30
                        },
                        'adom-rev-max-revisions': {
                            'type': 'integer',
                            'default': 120,
                            'example': 120
                        },
                        'adom-select': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'adom-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'clt-cert-req': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable',
                                'optional'
                            ]
                        },
                        'console-output': {
                            'type': 'string',
                            'enum': [
                                'standard',
                                'more'
                            ]
                        },
                        'country-flag': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'create-revision': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'daylightsavetime': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'default-disk-quota': {
                            'type': 'integer',
                            'default': 1000,
                            'example': 1000
                        },
                        'detect-unregistered-log-device': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'device-view-mode': {
                            'type': 'string',
                            'enum': [
                                'regular',
                                'tree'
                            ]
                        },
                        'dh-params': {
                            'type': 'string',
                            'enum': [
                                '1024',
                                '1536',
                                '2048',
                                '3072',
                                '4096',
                                '6144',
                                '8192'
                            ]
                        },
                        'disable-module': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'fortiview-noc'
                                ]
                            }
                        },
                        'enc-algorithm': {
                            'type': 'string',
                            'enum': [
                                'low',
                                'medium',
                                'high'
                            ]
                        },
                        'faz-status': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'fgfm-local-cert': {
                            'type': 'string'
                        },
                        'fgfm-ssl-protocol': {
                            'type': 'string',
                            'enum': [
                                'sslv3',
                                'tlsv1.0',
                                'tlsv1.1',
                                'tlsv1.2'
                            ]
                        },
                        'ha-member-auto-grouping': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'hitcount_concurrent': {
                            'type': 'integer',
                            'default': 100,
                            'example': 100
                        },
                        'hitcount_interval': {
                            'type': 'integer',
                            'default': 300,
                            'example': 300
                        },
                        'hostname': {
                            'type': 'string'
                        },
                        'import-ignore-addr-cmt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'language': {
                            'type': 'string',
                            'enum': [
                                'english',
                                'simch',
                                'japanese',
                                'korean',
                                'spanish',
                                'trach'
                            ]
                        },
                        'latitude': {
                            'type': 'string'
                        },
                        'ldap-cache-timeout': {
                            'type': 'integer',
                            'default': 86400,
                            'example': 86400
                        },
                        'ldapconntimeout': {
                            'type': 'integer',
                            'default': 60000,
                            'example': 60000
                        },
                        'lock-preempt': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'log-checksum': {
                            'type': 'string',
                            'enum': [
                                'none',
                                'md5',
                                'md5-auth'
                            ]
                        },
                        'log-forward-cache-size': {
                            'type': 'integer',
                            'default': 0,
                            'example': 0
                        },
                        'longitude': {
                            'type': 'string'
                        },
                        'max-log-forward': {
                            'type': 'integer',
                            'default': 5,
                            'example': 5
                        },
                        'max-running-reports': {
                            'type': 'integer',
                            'default': 1,
                            'example': 1
                        },
                        'oftp-ssl-protocol': {
                            'type': 'string',
                            'enum': [
                                'sslv3',
                                'tlsv1.0',
                                'tlsv1.1',
                                'tlsv1.2'
                            ]
                        },
                        'partial-install': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'partial-install-force': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'partial-install-rev': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'perform-improve-by-ha': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policy-hit-count': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'policy-object-in-dual-pane': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'pre-login-banner': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'pre-login-banner-message': {
                            'type': 'string'
                        },
                        'remoteauthtimeout': {
                            'type': 'integer',
                            'default': 10,
                            'example': 10
                        },
                        'search-all-adoms': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-low-encryption': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'ssl-protocol': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'tlsv1.2',
                                    'tlsv1.1',
                                    'tlsv1.0',
                                    'sslv3'
                                ]
                            }
                        },
                        'ssl-static-key-ciphers': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'task-list-size': {
                            'type': 'integer',
                            'default': 2000,
                            'example': 2000
                        },
                        'tftp': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'timezone': {
                            'type': 'string',
                            'enum': [
                                '00',
                                '01',
                                '02',
                                '03',
                                '04',
                                '05',
                                '06',
                                '07',
                                '08',
                                '09',
                                '10',
                                '11',
                                '12',
                                '13',
                                '14',
                                '15',
                                '16',
                                '17',
                                '18',
                                '19',
                                '20',
                                '21',
                                '22',
                                '23',
                                '24',
                                '25',
                                '26',
                                '27',
                                '28',
                                '29',
                                '30',
                                '31',
                                '32',
                                '33',
                                '34',
                                '35',
                                '36',
                                '37',
                                '38',
                                '39',
                                '40',
                                '41',
                                '42',
                                '43',
                                '44',
                                '45',
                                '46',
                                '47',
                                '48',
                                '49',
                                '50',
                                '51',
                                '52',
                                '53',
                                '54',
                                '55',
                                '56',
                                '57',
                                '58',
                                '59',
                                '60',
                                '61',
                                '62',
                                '63',
                                '64',
                                '65',
                                '66',
                                '67',
                                '68',
                                '69',
                                '70',
                                '71',
                                '72',
                                '73',
                                '74',
                                '75',
                                '76',
                                '77',
                                '78',
                                '79',
                                '80',
                                '81',
                                '82',
                                '83',
                                '84',
                                '85',
                                '86',
                                '87',
                                '88',
                                '89'
                            ]
                        },
                        'tunnel-mtu': {
                            'type': 'integer',
                            'default': 1500,
                            'example': 1500
                        },
                        'usg': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'vdom-mirror': {
                            'type': 'string',
                            'enum': [
                                'disable',
                                'enable'
                            ]
                        },
                        'webservice-proto': {
                            'type': 'array',
                            'items': {
                                'type': 'string',
                                'enum': [
                                    'tlsv1.2',
                                    'tlsv1.1',
                                    'tlsv1.0',
                                    'sslv3',
                                    'sslv2'
                                ]
                            }
                        },
                        'workflow-max-sessions': {
                            'type': 'integer',
                            'default': 500,
                            'example': 500
                        },
                        'workspace-mode': {
                            'type': 'string',
                            'enum': [
                                'disabled',
                                'normal',
                                'workflow'
                            ]
                        }
                    },
                    'api_tag': 0
                },
                {
                    'type': 'string',
                    'name': 'url',
                    'api_tag': 0
                }
            ]
        },
        'method_mapping': {
            'get': 'object0',
            'set': 'object1',
            'update': 'object1'
        }
    }

    module_arg_spec = {
        'loose_validation': {
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
        'params': {
            'type': 'list',
            'required': False
        },
        'method': {
            'type': 'str',
            'required': True,
            'choices': [
                'get',
                'set',
                'update'
            ]
        },
        'url_params': {
            'type': 'dict',
            'required': False
        }
    }
    module = AnsibleModule(argument_spec=module_arg_spec,
                           supports_check_mode=False)
    method = module.params['method']
    loose_validation = module.params['loose_validation']

    fmgr = None
    payload = None
    response = DEFAULT_RESULT_OBJ

    if module._socket_path:
        connection = Connection(module._socket_path)
        tools = FMGRCommon()
        if loose_validation == False:
            tools.validate_module_params(module, body_schema)
        tools.validate_module_url_params(module, jrpc_urls, url_schema)
        full_url = tools.get_full_url_path(module, jrpc_urls)
        payload = tools.get_full_payload(module, full_url)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = tools
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    try:
        response = fmgr._conn.send_request(method, payload)
        fmgr.govern_response(module=module, results=response,
                             msg='Operation Finished',
                             ansible_facts=fmgr.construct_ansible_facts(response, module.params, module.params))
    except Exception as e:
        raise FMGBaseException(e)

    module.exit_json(meta=response[1])


if __name__ == '__main__':
    main()
