import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('lab', Path(__file__).with_name('lab.py'))
lab = importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)


class LabTests(unittest.TestCase):
    def test_projection_keeps_original_and_requires_confirmed_windows_time(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(lab, 'LAB', Path(temporary)):
            (lab.LAB/'splunk-aws.json').write_text(json.dumps({'eventTime':'2026-01-01T00:00:00Z',
                'eventName':'ConsoleLogin','responseElements':{'ConsoleLogin':'Failure'},
                'sourceIPAddress':'203.0.113.77','userIdentity':{'accountId':'111111111111','userName':'synthetic'}}))
            (lab.LAB/'splunk-windows.log').write_text('01/01/2026 01:00:00 PM\nEventCode=4688\nComputerName=lab-host\n')
            with self.assertRaises(ValueError):list(lab.records(None))
            events=list(lab.records('+01:00'))
            self.assertEqual(events[0]['event']['outcome'],'failure')
            self.assertEqual(events[1]['event']['outcome'],'unknown')
            self.assertEqual(events[1]['@timestamp'],'2026-01-01T12:00:00+00:00')
            self.assertIn('EventCode=4688',events[1]['event']['original'])
            self.assertEqual(events[1]['irmind_validation']['confirmed_utc_offset'],'+01:00')

    def test_redirect_with_admin_auth_is_rejected(self):
        with self.assertRaises(ValueError):
            lab.NoRedirect().redirect_request(None,None,None,None,None,'https://elsewhere.invalid')

    def test_key_output_inside_checkout_is_rejected_before_network(self):
        with self.assertRaises(ValueError):lab.create_key(lab.ROOT/'ignored-key.txt')


if __name__=='__main__':unittest.main()
