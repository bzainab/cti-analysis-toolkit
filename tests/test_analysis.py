import unittest
from analyze import triage,correlate,normalize_indicator,indicators_to_stix,navigator_layer
class AnalysisTests(unittest.TestCase):
 def setUp(self):
  self.asset=dict(asset='test-gateway',cve='CVE-2024-3400',internet_exposed='true',criticality='5',cvss='10',owner='Demo')
  self.kev=dict(id='CVE-2024-3400',ransomware=True,epss=.8,epssDate='2026-09-01',action='Apply update')
 def test_exposed_critical_kev_is_p1(self):
  r=triage(self.asset,self.kev);self.assertEqual(r['priority'],'P1');self.assertEqual(r['score'],97)
 def test_missing_epss_remains_explicit(self):
  r=triage(self.asset,{**self.kev,'epss':None});self.assertIn('EPSS unknown', ' '.join(r['reasons']))
 def test_no_kev_is_not_safe(self):
  self.assertIn('absence is not evidence of safety',' '.join(triage(self.asset,None)['reasons']))
 def test_deduplicate_pairs(self):
  self.assertEqual(len(correlate([self.asset,self.asset],{'vulnerabilities':[self.kev]})),1)
 def test_invalid_cvss_rejected(self):
  with self.assertRaises(ValueError):triage({**self.asset,'cvss':'11'},self.kev)
 def test_fractional_criticality_rejected(self):
  with self.assertRaises(ValueError):triage({**self.asset,'criticality':'2.5'},self.kev)
 def test_invalid_exposure_rejected(self):
  with self.assertRaises(ValueError):triage({**self.asset,'internet_exposed':'yes'},self.kev)
 def test_invalid_cve_rejected(self):
  with self.assertRaises(ValueError):correlate([{**self.asset,'cve':'test'}],{'vulnerabilities':[]})
 def test_defanged_domain(self):self.assertEqual(normalize_indicator('EXAMPLE[.]ORG'),('domain-name','example.org'))
 def test_ipv6(self):self.assertEqual(normalize_indicator('2001:db8::1')[0],'ipv6-addr')
 def test_sha256(self):self.assertEqual(normalize_indicator('a'*64)[0],'file')
 def test_stix_deduplicates_and_escapes(self):
  b=indicators_to_stix(['example.org','example[.]org',"https://example.org/a'b"])
  self.assertEqual(len(b['objects']),2);self.assertIn("a\\'b",b['objects'][1]['pattern'])
 def test_no_ambiguous_group_match(self):
  with self.assertRaises(ValueError):navigator_layer({'groups':[]},'FIN7')
if __name__=='__main__':unittest.main()
