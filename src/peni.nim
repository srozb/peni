import strutils
import cligen

import peni/cmdInfo
import peni/cmdHash
import peni/cmdGrep
import peni/cmdEntropy
import peni/cmdBaseline


dispatchMulti(
    [info, help = {
      "all": "show everything",
      "summary": "short summary (default)",
      "headers": "headers",
      "sections": "sections",
      "directories": "directories",
      "imports": "imports",
      "exports": "exports",
      "recursive": "be recursive",
      }, short = {
      "headers": 'H',
      "sections": 'S'
    }
    ],
    [grep, help={
      "imports": "in imports",
      "exports": "in exports",
      "pattern": "pattern to match with",
      "recursive": "be recursive"
    }, short={
      "imports": 'I',
      "exports": 'E'
    }],
    [hash, help={
      "imphash": "imphash",
      "md5": "md5",
      "sha1": "sha1",
      "sha256": "sha256",
      "ssdeep", "ssdeep",
      "recursive": "be recursive"
    }, short={
      "sha256": 'S',
      "ssdeep": 'd'
    }],
    [entropy, help={
      "recursive": "be recursive"
    }],
    [baseline, help={
      "recursive": "be recursive",
      "bloomSize": "bloom filter expected capacity",
      "errorRate": "bloom filter expected error-rate",
      "nsrl": "convert nsrl filelist rather than generating a new filelist"
    }, short={
      "bloomSize": 's'
    }]
  )