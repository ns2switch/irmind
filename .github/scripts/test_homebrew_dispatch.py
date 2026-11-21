from pathlib import Path
import unittest
class HomebrewDispatchTests(unittest.TestCase):
 def test_dispatch_is_tag_only_protected_and_after_verified_installers(self):
  job=(Path(__file__).parents[1]/'workflows/ci.yml').read_text().split('  update_homebrew:\n',1)[1]
  for required in ('environment: release',"github.event_name == 'push'","startsWith(github.ref, 'refs/tags/v')",'secrets.HOMEBREW_TAP_TOKEN','needs: post_release', "needs.post_release.result == 'success'", 'gh workflow run update.yml --repo ns2switch/homebrew-irmind --ref main'):
   self.assertIn(required,job)
  self.assertNotIn('contents: write',job)
  self.assertNotIn('repository_dispatch',job)
if __name__=='__main__':unittest.main()
