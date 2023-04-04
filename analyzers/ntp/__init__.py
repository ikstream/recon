import json
import packaging.version
import re

from .. import AbstractAnalyzer

SERVICE_SCHEMA = {
  'address': None,
  'transport_protocol': None,
  'port': None,
  'version': None, # e.g. "4.2.8p15"
  'monlist': [],
  'info': [],
  'issues': [],
}

class Analyzer(AbstractAnalyzer):

  def __init__(self, recommendations):
    super().__init__(recommendations)

    self.name = 'ntp'
    self.set_tool('nmap')

  def analyze(self, files):
    super().analyze(files)

    # parse result files
    services = self.parser.parse_files(files[self.tool])
    self.services = services

    # analyze services based on recommendations

    for identifier, service in services.items():
      issues = service['issues']

      if 'version' in self.recommendations:
        self.analyze_version(
          service['version'],
          self.recommendations['version'],
          issues
        )

      if len(service['monlist']):
        issues.append("could be abused for traffic amplification attacks (CVE-2013-5211)")
        # https://nvd.nist.gov/vuln/detail/CVE-2013-5211

      for info in service['monlist']:
        issues.append(f"received data: `{info}`")

      if len(service['info']):
        issues.append("vulnerable to information disclosure and could be abused for traffic amplification attacks")

      for info in service['info']:
        issues.append(f"received data: `{info}`")

    return services

  def analyze_version(self, version, recommendation, issues):
    if version == recommendation:
      return

    v = packaging.version.parse(version)
    r = packaging.version.parse(recommendation)

    if v < r:
      issues.append(f"outdated version: {version} < {recommendation}")
