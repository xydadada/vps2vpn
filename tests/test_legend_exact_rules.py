"""An old DOMAIN rule does not cover subdomains or an entire later suffix."""
import unittest

from tests.test_legend_import import first_match, li, rules


class ExactRuleScope(unittest.TestCase):
    def test_exact_parent_does_not_drop_a_child_rule(self):
        lists, report = li.convert_rules([
            'DOMAIN,parent.example,PROXY',
            'DOMAIN-SUFFIX,child.parent.example,DIRECT',
        ])
        self.assertEqual(report['dead'], 0)
        self.assertEqual(lists['direct'], ['child.parent.example'])
        plan = rules.route_plan({'custom_proxy': lists['proxy'], 'custom_direct': lists['direct']})
        self.assertEqual(first_match(plan, 'child.parent.example'), 'direct')
        self.assertEqual(first_match(plan, 'parent.example'), 'proxy')

    def test_exact_name_does_not_hide_the_rest_of_a_later_suffix(self):
        lists, report = li.convert_rules([
            'DOMAIN,parent.example,PROXY',
            'DOMAIN-SUFFIX,parent.example,DIRECT',
        ])
        self.assertEqual(report['dead'], 0)
        self.assertEqual(lists['proxy'], ['parent.example'])
        self.assertEqual(lists['direct'], ['parent.example'])
        self.assertEqual(report['shadowed'], [('parent.example', 'proxy', 'parent.example', 'direct')])

    def test_true_exact_and_suffix_duplicates_remain_dead(self):
        for previous, current in [
            ('DOMAIN,parent.example,PROXY', 'DOMAIN,parent.example,DIRECT'),
            ('DOMAIN-SUFFIX,parent.example,PROXY', 'DOMAIN,child.parent.example,DIRECT'),
            ('DOMAIN-SUFFIX,parent.example,PROXY', 'DOMAIN-SUFFIX,child.parent.example,DIRECT'),
        ]:
            with self.subTest(previous=previous, current=current):
                lists, report = li.convert_rules([previous, current])
                self.assertEqual(report['dead'], 1)
                self.assertEqual(lists['direct'], [])
