import copy
import unittest
import analyze


def request(system='S', tools=None, user='U'):
    return {'tools': tools or [], 'messages': [
        {'role':'System','content':system,'tool_calls':[],'tool_call_id':None},
        {'role':'User','content':user,'tool_calls':[],'tool_call_id':None}]}


def row(value):
    return {'turn':1,'request':value,'simulated_usage':{'input_tokens':analyze.tokens(value),'output_tokens':1}}


class Measurements(unittest.TestCase):
    def test_cache_cost_does_not_remove_tokens_from_the_case_budget(self):
        value=request(system='S'*8192)
        measured=analyze.analyze([row(value),row(value)])
        self.assertEqual(measured['input_tokens_sim'],2*analyze.tokens(value))
        self.assertGreater(measured['head_only_cache_reads_sim'],0)
        self.assertLess(measured['head_only_input_cost_units_at_read_0_1_write_1_25'],measured['input_tokens_sim'])

    def test_head_matching_requires_the_pair_not_independent_seen_components(self):
        tools1=[{'name':'one','description':'A'*8192}]
        tools2=[{'name':'two','description':'B'*8192}]
        values=[request('S1',tools1),request('S2',tools2),request('S1',tools2)]
        self.assertEqual(analyze.analyze(list(map(row,values)))['head_only_cache_reads_sim'],0)

    def test_child_contexts_are_never_pooled(self):
        system='You are an IRMind subagent. '+'S'*8192
        values=[request(system,user='task A'),request(system,user='task B')]
        measured=analyze.analyze(list(map(row,values)))
        self.assertEqual(measured['cache_read_ceiling_sim'],0)
        self.assertEqual(measured['head_only_cache_reads_sim'],0)

    def test_oracles_do_not_mutate_observed_input(self):
        value=request(user='<UNTRUSTED_12345678-1234-1234-1234-123456789012> data')
        value['messages'].append({'role':'Tool','content':'é'*4000,'tool_calls':[],'tool_call_id':'x'})
        before=copy.deepcopy(value)
        changed=analyze.paged_size_oracle(value)
        self.assertLess(analyze.tokens(changed),analyze.tokens(value))
        self.assertNotEqual(analyze.frozen_archive_oracle(value),value)
        self.assertEqual(value,before)


if __name__=='__main__': unittest.main()
