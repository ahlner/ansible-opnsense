from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.api import \
    Session
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.translate import \
    get_key_by_value_from_selection
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.validate import \
    is_unset
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.rule import \
    validate_values
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.module import BaseModule


class SNat(BaseModule):
    CMDS = {
        'add': 'add_rule',
        'del': 'del_rule',
        'set': 'set_rule',
        'search': 'search_rule',
        'detail': 'get_rule',
        'toggle': 'toggle_rule',
    }
    API_KEY_PATH = 'rule'
    API_MOD = 'firewall'
    API_CONT = 'source_nat'
    FIELDS_CHANGE = [
        'sequence', 'no_nat', 'interface', 'target', 'target_port', 'description',
        'ip_protocol', 'protocol', 'source_invert', 'source_net', 'source_port',
        'destination_invert', 'destination_net', 'destination_port', 'log', 'static_port',
        'categories',
    ]
    FIELDS_ALL = ['enabled']
    FIELDS_ALL.extend(FIELDS_CHANGE)
    FIELDS_TRANSLATE = {
        'ip_protocol': 'ipprotocol',
        'source_invert': 'source_not',
        'destination_invert': 'destination_not',
        'no_nat': 'nonat',
        'static_port': 'staticnatport',
    }
    FIELDS_TYPING = {
        'bool': ['enabled', 'log', 'source_invert', 'no_nat', 'destination_invert', 'static_port'],
        'list': [],
        'select': ['interface', 'ip_protocol', 'protocol'],
        'int': [],
        'list_value': ['categories'],
    }
    INT_VALIDATIONS = {
        'sequence': {'min': 1, 'max': 99999},
    }
    EXIST_ATTR = 'rule'
    API_CMD_REL = 'apply'

    def __init__(self, module: AnsibleModule, result: dict, session: Session = None, fail: dict = None):
        BaseModule.__init__(self=self, m=module, r=result, s=session, f=fail)
        self.rule = {}

    def check(self) -> None:
        if self.p['state'] == 'present':
            if is_unset(self.p['interface']):
                self.m.fail_json(
                    "You need to provide an 'interface' to create a source-nat rule!"
                )

            if is_unset(self.p['target']):
                self.m.fail_json(
                    "You need to provide an 'target' to create a source-nat rule!"
                )

        self._build_log_name()
        self.find(match_fields=self.p['match_fields'])

        if self.p['state'] == 'present':
            validate_values(module=self.m, cnf=self.p, error_func=self.m.fail_json, kind='nat')

        self._base_check()

    def _build_log_name(self) -> str:
        if self.p['description'] not in [None, '']:
            log_name = self.p['description']

        else:
            log_name = 'FROM '

            if self.p['source_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['source_net']} <= PROTO {self.p['protocol']} => "

            if self.p['destination_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['destination_net']}:{self.p['destination_port']} "
            log_name += f" =NAT=> {self.p['target']}:{self.p['target_port']}"

        return log_name

    def _get_category_selection(self) -> dict:
        def extract_selection(ruleset) -> dict:
            if not isinstance(ruleset, dict):
                return {}

            if self.exists and self.field_pk in self.rule and self.rule[self.field_pk] in ruleset:
                return ruleset[self.rule[self.field_pk]].get('categories', {})

            for entry in ruleset.values():
                if isinstance(entry, dict) and 'categories' in entry:
                    return entry['categories']

            return {}

        rules = self._api_get({
            **self.call_cnf,
            'command': self.CMDS['search'],
        })

        if isinstance(rules, dict):
            rows = rules.get('rows', [])
            if isinstance(rows, list):
                selection = {}
                for entry in rows:
                    if not isinstance(entry, dict):
                        continue

                    for category in entry.get('category_colors', []):
                        if not isinstance(category, dict):
                            continue

                        category_id = category.get('uuid')
                        category_name = category.get('name')
                        if category_id and category_name:
                            selection[category_id] = {'value': category_name}

                    category_ids = entry.get('categories', '')
                    category_names = entry.get('%categories', '')
                    if category_ids and category_names:
                        ids = [value.strip() for value in category_ids.split(self.RESP_JOIN_CHAR) if value.strip()]
                        names = [value.strip() for value in category_names.split(self.RESP_JOIN_CHAR) if value.strip()]
                        if len(ids) == len(names):
                            selection.update({
                                category_id: {'value': category_name}
                                for category_id, category_name in zip(ids, names)
                            })

                if len(selection) > 0:
                    return selection

            selection = extract_selection(self._search_path_handling(rules))
            if len(selection) > 0:
                return selection

        for controller, ak_path in (
            ('filter', 'filter.rules.rule'),
            ('one_to_one', 'filter.onetoone.rule'),
        ):
            selection = extract_selection(self._search_path_handling(
                self._api_get({
                    'module': self.API_MOD,
                    'controller': controller,
                    'command': 'get',
                }),
                ak_path=ak_path,
            ))
            if len(selection) > 0:
                return selection

        return {}

    def build_request(self) -> dict:
        raw_request = self._base_build_request()

        if not is_unset(self.p['categories']):
            selection = self._get_category_selection()
            category_ids = []
            for category in self.p['categories']:
                category_id = get_key_by_value_from_selection(selection=selection, value=category)
                if category_id is None:
                    self.m.fail_json(f"Unable to resolve rule category '{category}'")

                category_ids.append(category_id)

            raw_request['rule']['categories'] = self.RESP_JOIN_CHAR.join(category_ids)

        return raw_request
