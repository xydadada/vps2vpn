"""Issue #180: server groups must not shadow client policy names."""
from unittest import mock

from tests import test_unit as tu
from vps2vpn import db, subscription


# chen08209/Clash.Meta@5b453f80, config/config.go:892-898.
MIHOMO_POLICIES = {'DIRECT', 'REJECT', 'REJECT-DROP', 'COMPATIBLE', 'PASS', 'PASS-RULE'}
RESERVED = MIHOMO_POLICIES | {'GLOBAL', 'direct'}


class ReservedPolicies(tu.Base):
    def setUp(self):
        super().setUp()
        self.user = dict(db.user(db.add_user('synthetic', 10)),
                         uuid='00000000-0000-4000-8000-000000000001', hy2_pass='REDACTED')
        for target, value in (
            ('vps2vpn.subscription.tls_info', {'sni': 'example.com', 'pin': '', 'pem': ''}),
            ('vps2vpn.shaper.active', False),
            ('vps2vpn.aicheck.latest', None),
        ):
            patch = mock.patch(target, return_value=value)
            patch.start()
            self.addCleanup(patch.stop)

    def settings(self, main, remote='Example-B', language='en'):
        s = dict(db.settings(), node_name=main, public_host='198.51.100.1', domain='',
                 hy2_enabled=True, reality_enabled=False, tuic_enabled=False, hy2_hop=False,
                 hy2_obfs='', language=language, servers=[])
        if remote is not None:
            info = dict(s, public_host='198.51.100.2',
                        tls={'sni': 'example.com', 'pin': '', 'pem': ''})
            s['servers'] = [{'id': 'abcd1234', 'name': remote, 'enabled': True, 'info': info,
                             'idmap': {str(self.user['id']): 2}}]
        return s

    def outputs(self, s):
        return (subscription.clash(s, self.user, 'https://example.com'),
                subscription.singbox(s, self.user, 'https://example.com'))

    def assert_contracts(self, s):
        clash, sb = self.outputs(s)
        group_names = [group['name'] for group in clash['proxy-groups']]
        proxy_names = [proxy['name'] for proxy in clash['proxies']]
        names = group_names + proxy_names
        self.assertEqual(len(names), len(set(names)))
        self.assertFalse(RESERVED.intersection(group_names), group_names)
        for group in clash['proxy-groups']:
            for ref in group['proxies']:
                self.assertIn(ref, set(names) | MIHOMO_POLICIES)
        for rule in clash['rules']:
            fields = rule.split(',')
            target = fields[-2] if fields[-1] == 'no-resolve' else fields[-1]
            self.assertIn(target, set(names) | MIHOMO_POLICIES)
        tags = [out['tag'] for out in sb['outbounds']]
        self.assertEqual(len(tags), len(set(tags)))
        for out in sb['outbounds']:
            for ref in out.get('outbounds', []):
                self.assertIn(ref, tags)
            if 'default' in out:
                self.assertIn(out['default'], out['outbounds'])
        self.assertIn(sb['route']['final'], tags)
        for rule in sb['route']['rules']:
            if 'outbound' in rule:
                self.assertIn(rule['outbound'], tags)
        for resolver in sb['dns']['servers']:
            if 'detour' in resolver:
                self.assertIn(resolver['detour'], tags)
        for rule_set in sb['route']['rule_set']:
            self.assertIn(rule_set['download_detour'], tags)
        per = subscription.server_groups(subscription.nodes(s, self.user))
        if len(per) > 1:
            for label, members in per:
                group = next(group for group in clash['proxy-groups'] if group['name'] == label)
                outbound = next(out for out in sb['outbounds'] if out['tag'] == label)
                self.assertEqual(group['proxies'], members)
                self.assertEqual(outbound['outbounds'], members)
        self.assertEqual((clash, sb), self.outputs(s))
        return clash, sb

    def test_fixed_core_policy_table_is_reserved(self):
        self.assertTrue(RESERVED <= subscription.CLIENT_RESERVED,
                        RESERVED - subscription.CLIENT_RESERVED)

    def test_all_reserved_names_on_main_and_remote_in_both_languages(self):
        for name in sorted(RESERVED):
            for language in ('en', 'zh'):
                for main, remote in ((name, 'Example-B'), ('Example-A', name)):
                    with self.subTest(name=name, language=language, main=main):
                        s = self.settings(main, remote, language)
                        self.assert_contracts(s)
                        groups = dict(subscription.server_groups(subscription.nodes(s, self.user)))
                        self.assertIn(name + '_', groups)
                        self.assertIn(name + ' Hysteria2', groups[name + '_'])

    def test_localized_built_in_names_still_avoid_collisions(self):
        labels = {name for groups in subscription.GROUP_NAMES.values() for name in groups.values()}
        for name in sorted(labels):
            for language in ('en', 'zh'):
                with self.subTest(name=name, language=language):
                    s = self.settings(name, language=language)
                    self.assert_contracts(s)
                    self.assertIn(name + '_', dict(subscription.server_groups(
                        subscription.nodes(s, self.user))))

    def test_suffix_collisions_are_unique_and_stable_in_both_orders(self):
        for main, remote in (('PASS-RULE', 'PASS-RULE_'), ('PASS-RULE_', 'PASS-RULE')):
            with self.subTest(main=main):
                s = self.settings(main, remote)
                self.assert_contracts(s)
                groups = dict(subscription.server_groups(subscription.nodes(s, self.user)))
                self.assertEqual(list(groups), ['PASS-RULE_', 'PASS-RULE__'])
                self.assertEqual(list(groups.values()), [[main + ' Hysteria2'], [remote + ' Hysteria2']])

    def test_node_name_collisions_remain_reserved(self):
        s = self.settings('Example-A', 'Example-A Hysteria2')
        self.assert_contracts(s)
        groups = dict(subscription.server_groups(subscription.nodes(s, self.user)))
        self.assertEqual(list(groups), ['Example-A', 'Example-A Hysteria2_'])

    def test_ordinary_names_and_single_server_outputs_do_not_change(self):
        for main, remote in (('Example-A', 'Example-B'), ('pass-rule', 'PASS-Rule'),
                             ('PASS-RULE', None), ('Example-A', None)):
            for language in ('en', 'zh'):
                with self.subTest(main=main, remote=remote, language=language):
                    s = self.settings(main, remote, language)
                    outputs = self.assert_contracts(s)
                    with mock.patch.object(subscription, 'CLIENT_RESERVED',
                                           subscription.CLIENT_RESERVED - {'PASS-RULE'}):
                        self.assertEqual(outputs, self.outputs(s))
                    self.assertEqual([p['name'] for p in outputs[0]['proxies']],
                                     [name + ' Hysteria2' for name in (main, remote) if name is not None])
