import copy
import json

from .. import Issue, AbstractParser
from . import SERVICE_SCHEMA

class Parser(AbstractParser):
  '''
  parse results of the `ntp` scanner.

  $ ntp --json "{result_file}.json" {address} 2>&1 | tee "{result_file}.log"
  '''

  def __init__(self):
    super().__init__()

    self.name = 'ntp'
    self.file_type = 'json'

  def parse_file(self, path):
    super().parse_file(path)

    with open(path) as f:
      result = json.load(f)

    identifier = f"{result['address']}:{result['port']} ({self.transport_protocol})"
    if identifier in self.services:
      return

    service = copy.deepcopy(SERVICE_SCHEMA)
    service.update(result)

    if 'tests' in service and '2' in service['tests']:
      ntp_v2 = service['tests']['2']

      if '6' in ntp_v2 and ntp_v2['6']:
        mode_6 = ntp_v2['6']
        for opcode, result in mode_6.items():
          amplification_factor = result['amplification_factor']
          service['issues'].append(
            Issue(
              "mode 6",
              opcode = opcode,
              amplification_factor = amplification_factor,
            )
          )

          for data in result['data']:
            service['misc'].append(data)

      if '7' in ntp_v2 and ntp_v2['7']:
        mode_7 = ntp_v2['7']
        for implementation, request_codes in mode_7.items():
          for req_code, result in request_codes.items():
            amplification_factor = result['amplification_factor']
            service['issues'].append(
              Issue(
                "mode 7",
                implementation = implementation,
                req_code = req_code,
                amplification_factor = amplification_factor
              )
            )

            for data in result['data']:
              service['misc'].append(data)

    self.services[identifier] = service
