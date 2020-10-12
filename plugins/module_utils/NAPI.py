# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2020 Fortinet, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import _load_params
import sys


def check_galaxy_version(schema):
    params = _load_params()
    params_keys = list(params.keys())
    if 'method' in params_keys and 'method' not in schema:
        error_message = 'Legacy playbook detected, please revise the playbook or install latest legacy'
        error_message += ' fortimanager galaxy collection: #ansible-galaxy collection install -f fortinet.fortimanager:1.0.5'
        sys.stderr.write(error_message)
        sys.exit(1)


def check_parameter_bypass(schema, module_level2_name):
    params = _load_params()
    if 'bypass_validation' in params and params['bypass_validation'] is True:
        top_level_schema = dict()
        for key in schema:
            if key != module_level2_name:
                top_level_schema[key] = schema[key]
            else:
                top_level_schema[module_level2_name] = dict()
                top_level_schema[module_level2_name]['required'] = False
                top_level_schema[module_level2_name]['type'] = 'dict'
        return top_level_schema
    return schema


class NAPIManager(object):
    jrpc_urls = None
    perobject_jrpc_urls = None
    module_primary_key = None
    url_params = None
    module = None
    conn = None
    module_name = None
    module_level2_name = None
    top_level_schema_name = None

    def __init__(self, jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, conn, top_level_schema_name=None):
        self.jrpc_urls = jrpc_urls
        self.perobject_jrpc_urls = perobject_jrpc_urls
        self.module_primary_key = module_primary_key
        self.url_params = url_params
        self.module = module
        self.conn = conn
        self.process_workspace_lock()
        self.module_name = self.module._name
        self.module_level2_name = self.module_name.split('.')[-1][5:]
        self.top_level_schema_name = top_level_schema_name

    def process_workspace_lock(self):
        self.conn.process_workspace_locking(self.module.params)

    def _get_basic_url(self, is_perobject):
        url_libs = None
        if is_perobject:
            url_libs = [i for i in self.perobject_jrpc_urls]
        else:
            url_libs = [i for i in self.jrpc_urls]
        for uparam in self.url_params:
            if not self.module.params[uparam]:
                raise AssertionError('param %s MUST NOT be empty' % (uparam))
        the_url = None
        if 'adom' in self.url_params and not url_libs[0].endswith('{adom}'):
            adom = self.module.params['adom']
            if adom == 'global':
                for url in url_libs:
                    if '/global/' in url:
                        the_url = url
                        break
                if not the_url:
                    self.module.fail_json(msg='No global url for the request, please use other adom.')
            else:
                for url in url_libs:
                    if '/adom/{adom}/' in url:
                        the_url = url
                        break
                if not the_url:
                    self.module.fail_json(msg='No url for the requested adom:%s, please use other adom.' % (adom))
        else:
            the_url = url_libs[0]
        if not the_url:
            raise AssertionError('the_url is not expected to be NULL')
        for uparam in self.url_params:
            token_hint = '/%s/{%s}/' % (uparam, uparam)
            token = '/%s/%s/' % (uparam, self.module.params[uparam])
            the_url = the_url.replace(token_hint, token)
        return the_url

    def _get_base_perobject_url(self, mvalue):
        url_getting = self._get_basic_url(True)
        last_token = url_getting.split('/')[-1]
        second_last_token = url_getting.split('/')[-2]
        if last_token != '{' + second_last_token + '}':
            raise AssertionError('wrong last_token received')
        return url_getting.replace('{' + second_last_token + '}', str(mvalue))

    def get_object(self, mvalue):
        url_getting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_getting}]
        response = self.conn.send_request('get', params)
        return response

    def update_object(self, mvalue):
        url_updating = self._get_base_perobject_url(mvalue)
        if not self.top_level_schema_name:
            raise AssertionError('top level schema name MUST NOT be NULL')
        params = [{'url': url_updating, self.top_level_schema_name: self.__tailor_attributes(self.module.params[self.module_level2_name])}]
        response = self.conn.send_request('update', params)
        return response

    def create_objejct(self):
        url_creating = self._get_basic_url(False)
        if not self.top_level_schema_name:
            raise AssertionError('top level schema name MUST NOT be NULL')
        params = [{'url': url_creating, self.top_level_schema_name: self.__tailor_attributes(self.module.params[self.module_level2_name])}]
        return self.conn.send_request('set', params)

    def delete_object(self, mvalue):
        url_deleting = self._get_base_perobject_url(mvalue)
        params = [{'url': url_deleting}]
        return self.conn.send_request('delete', params)

    def _process_with_mkey(self, mvalue):
        mobject = self.get_object(mvalue)
        if self.module.params['state'] == 'present':
            if mobject[0] == 0:
                return self.update_object(mvalue)
            else:
                return self.create_objejct()
        elif self.module.params['state'] == 'absent':
            # in case the `GET` method returns nothing... see module `fmgr_antivirus_mmschecksum`
            # if mobject[0] == 0:
            return self.delete_object(mvalue)
            # else:
            #    self.do_nonexist_exit()
        else:
            raise AssertionError('Not Reachable')

    def _process_without_mkey(self):
        if self.module.params['state'] == 'absent':
            self.module.fail_json(msg='this module doesn\'t not support state:absent because of no primary key.')
        return self.create_objejct()

    def process_generic(self, method, param):
        response = self.conn.send_request(method, param)
        self.do_exit(response)

    def process_exec(self):
        the_url = self.jrpc_urls[0]
        if 'adom' in self.url_params and not self.jrpc_urls[0].endswith('{adom}'):
            if self.module.params['adom'] == 'global':
                for _url in self.jrpc_urls:
                    if '/global/' in _url:
                        the_url = _url
                        break
            else:
                for _url in self.jrpc_urls:
                    if '/adom/{adom}/' in _url:
                        the_url = _url
                        break
        for _param in self.url_params:
            token_hint = '{%s}' % (_param)
            token = '%s' % (self.module.params[_param])
            the_url = the_url.replace(token_hint, token)

        api_params = [{'url': the_url}]
        if self.module_level2_name in self.module.params:
            if not self.top_level_schema_name:
                raise AssertionError('top level schema name MUST NOT be NULL')
            api_params[0][self.top_level_schema_name] = self.__tailor_attributes(self.module.params[self.module_level2_name])

        response = self.conn.send_request('exec', api_params)
        self.do_exit(response)

    def process_clone(self, metadata):
        if self.module.params['clone']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['clone']['selector']
        clone_params_schema = metadata[selector]['params']
        clone_urls = metadata[selector]['urls']
        real_params_keys = set()
        if self.module.params['clone']['self']:
            real_params_keys = set(self.module.params['clone']['self'].keys())
        if real_params_keys != set(clone_params_schema):
            self.module.fail_json(msg='expect params in self:%s, real params:%s' % (list(clone_params_schema), list(real_params_keys)))
        url = None
        if 'adom' in clone_params_schema and not clone_urls[0].endswith('{adom}'):
            if self.module.params['clone']['self']['adom'] == 'global':
                for _url in clone_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            else:
                for _url in clone_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        break
        else:
            url = clone_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (clone_urls))
        for _param in clone_params_schema:
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, self.module.params['clone']['self'][_param])
            url = url.replace(token_hint, token)
        mkey = metadata[selector]['mkey']
        if mkey and mkey not in self.module.params['clone']['target']:
            self.module.fail_json(msg='Must give the primary key/value in target: %s!' % (mkey))
        api_params = [{'url': url,
                       'data': self.module.params['clone']['target']}]
        response = self.conn.send_request('clone', api_params)
        self.do_exit(response)

    def process_move(self, metadata):
        if self.module.params['move']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['move']['selector']
        move_params = metadata[selector]['params']
        move_urls = metadata[selector]['urls']
        if not len(move_urls):
            raise AssertionError('unexpected move urls set')
        real_params_keys = set()
        if self.module.params['move']['self']:
            real_params_keys = set(self.module.params['move']['self'].keys())
        if real_params_keys != set(move_params):
            self.module.fail_json(msg='expect params in self:%s, real params:%s' % (list(move_params), list(real_params_keys)))

        url = None
        if 'adom' in move_params and not move_urls[0].endswith('{adom}'):
            if self.module.params['move']['self']['adom'] == 'global':
                for _url in move_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            else:
                for _url in move_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        break
        else:
            url = move_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (move_urls))
        for _param in move_params:
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, self.module.params['move']['self'][_param])
            url = url.replace(token_hint, token)

        api_params = [{'url': url,
                       'option': self.module.params['move']['action'],
                       'target': self.module.params['move']['target']}]
        response = self.conn.send_request('move', api_params)
        self.do_exit(response)

    def process_fact(self, metadata):
        if self.module.params['facts']['selector'] not in metadata:
            raise AssertionError('selector is expected in parameters')
        selector = self.module.params['facts']['selector']
        fact_params = metadata[selector]['params']
        fact_urls = metadata[selector]['urls']
        if not len(fact_urls):
            raise AssertionError('unexpected fact urls set')
        real_params_keys = set()
        if self.module.params['facts']['params']:
            real_params_keys = set(self.module.params['facts']['params'].keys())
        if real_params_keys != set(fact_params):
            self.module.fail_json(msg='expect params:%s, real params:%s' % (list(fact_params), list(real_params_keys)))
        url = None
        if 'adom' in fact_params and not fact_urls[0].endswith('{adom}'):
            if self.module.params['facts']['params']['adom'] == 'global':
                for _url in fact_urls:
                    if '/global/' in _url:
                        url = _url
                        break
            elif self.module.params['facts']['params']['adom'] != '' and self.module.params['facts']['params']['adom'] is not None:
                for _url in fact_urls:
                    if '/adom/{adom}/' in _url:
                        url = _url
                        # url = _url.replace('/adom/{adom}/', '/adom/%s/' % (self.module.params['facts']['params']['adom']))
                        break
            else:
                # choose default URL which is for all domains
                for _url in fact_urls:
                    if '/global/' not in _url and '/adom/{adom}/' not in _url:
                        url = _url
                        break
        else:
            url = fact_urls[0]
        if not url:
            self.module.fail_json(msg='can not find url in following sets:%s! please check params: adom' % (fact_urls))
        for _param in fact_params:
            _the_param = self.module.params['facts']['params'][_param]
            if self.module.params['facts']['params'][_param] is None:
                _the_param = ''
            token_hint = '/%s/{%s}' % (_param, _param)
            token = '/%s/%s' % (_param, _the_param)
            url = url.replace(token_hint, token)

        # Other Filters and Sorters
        filters = self.module.params['facts']['filter']
        sortings = self.module.params['facts']['sortings']
        fields = self.module.params['facts']['fields']
        options = self.module.params['facts']['option']

        api_params = [{'url': url}]
        if filters:
            api_params[0]['filter'] = filters
        if sortings:
            api_params[0]['sortings'] = sortings
        if fields:
            api_params[0]['fields'] = fields
        if options:
            api_params[0]['option'] = options

        # Now issue the request.
        response = self.conn.send_request('get', api_params)
        self.do_exit(response)

    def process_curd(self):
        if 'state' not in self.module.params:
            raise AssertionError('parameter state is expected')
        has_mkey = self.module_primary_key is not None
        if has_mkey:
            mvalue = ''
            if self.module_primary_key.startswith('complex:'):
                mvalue_exec_string = self.module_primary_key[len('complex:'):]
                mvalue_exec_string = mvalue_exec_string.replace('{{module}}', 'self.module.params[self.module_level2_name]')
                # mvalue_exec_string = 'mvalue = %s' % (mvalue_exec_string)
                # exec(mvalue_exec_string)
                # On Windows Platform, exec() call doesn't take effect.
                mvalue = eval(mvalue_exec_string)
            else:
                mvalue = self.module.params[self.module_level2_name][self.module_primary_key]
            self.do_exit(self._process_with_mkey(mvalue))
        else:
            self.do_exit(self._process_without_mkey())

    def __tailor_attributes(self, data):
        if type(data) == dict:
            rdata = dict()
            for key in data:
                value = data[key]
                if value is None:
                    continue
                rdata[key] = self.__tailor_attributes(value)
            return rdata
        elif type(data) == list:
            rdata = list()
            for item in data:
                if item is None:
                    continue
                rdata.append(self.__tailor_attributes(item))
            return rdata
        else:
            if data is None:
                raise AssertionError('data is expected to be not none')
            return data

    def process_partial_curd(self):
        the_url = self.jrpc_urls[0]
        if 'adom' in self.url_params and not self.jrpc_urls[0].endswith('{adom}'):
            if self.module.params['adom'] == 'global':
                for _url in self.jrpc_urls:
                    if '/global/' in _url:
                        the_url = _url
                        break
            else:
                for _url in self.jrpc_urls:
                    if '/adom/{adom}/' in _url:
                        the_url = _url
                        break
        for _param in self.url_params:
            token_hint = '{%s}' % (_param)
            token = '%s' % (self.module.params[_param])
            the_url = the_url.replace(token_hint, token)
        the_url = the_url.rstrip('/')
        api_params = [{'url': the_url}]
        if self.module_level2_name in self.module.params:
            if not self.top_level_schema_name:
                raise AssertionError('top level schem name is not supposed to be empty')
            api_params[0][self.top_level_schema_name] = self.__tailor_attributes(self.module.params[self.module_level2_name])
        response = self.conn.send_request('set', api_params)
        self.do_exit(response)

    def validate_parameters(self, pvb):
        for blob in pvb:
            attribute_path = blob['attribute_path']
            pointer = self.module.params
            ignored = False
            for attr in attribute_path:
                if attr not in pointer:
                    # If the parameter is not given, ignore that.
                    ignored = True
                    break
                pointer = pointer[attr]
            if ignored:
                continue
            lambda_expr = blob['lambda']
            lambda_expr = lambda_expr.replace('$', str(pointer))
            eval_result = eval(lambda_expr)
            if not eval_result:
                if 'fail_action' not in blob or blob['fail_action'] == 'warn':
                    self.module.warn(blob['hint_message'])
                else:
                    # assert blob['fail_action'] == 'quit':
                    self.module.fail_json(msg=blob['hint_message'])

    def _do_final_exit(self, rc, result):
        # XXX: as with https://github.com/fortinet/ansible-fortimanager-generic.
        # the failing conditions priority: failed_when > rc_failed > rc_succeeded.
        failed = rc != 0
        changed = rc == 0

        if 'response_code' not in result:
            raise AssertionError('response_code should be in result')
        if self.module.params['rc_failed']:
            for rc_code in self.module.params['rc_failed']:
                if str(result['response_code']) == str(rc_code):
                    failed = True
                    result['result_code_overriding'] = 'rc code:%s is overridden to failure' % (rc_code)
        elif self.module.params['rc_succeeded']:
            for rc_code in self.module.params['rc_succeeded']:
                if str(result['response_code']) == str(rc_code):
                    failed = False
                    result['result_code_overriding'] = 'rc code:%s is overridden to success' % (rc_code)
        self.module.exit_json(rc=rc, meta=result, failed=failed, changed=changed)

    def do_nonexist_exit(self):
        rc = 0
        result = dict()
        result['response_code'] = -3
        result['response_message'] = 'object not exist'
        self._do_final_exit(rc, result)

    def do_exit(self, response):
        rc = response[0]
        result = dict()
        result['response_data'] = list()
        if 'data' in response[1]:
            result['response_data'] = response[1]['data']
        result['response_code'] = response[1]['status']['code']
        result['response_message'] = response[1]['status']['message']
        result['request_url'] = response[1]['url']
        # XXX:Do further status mapping
        self._do_final_exit(rc, result)
