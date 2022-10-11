import strutils
import cligen

import peni/cmdInfo
import peni/cmdHash
import peni/cmdGrep
import peni/cmdEntropy

dispatchMulti(
  [info, help = {
    "all": "show everything",
    "summary": "short summary (default)",
    "headers": "headers",
    "sections": "sections",
    "directories": "directories",
    "imports": "imports",
    "exports": "exports",
    "authenticode": "authenticode",
    "recursive": "be recursive",
    }, short = {
    "headers": 'H',
    "sections": 'S',
    "authenticode": 'A'
  }
  ],
  [grep, help={
    "authenticode": "in authenticode",
    "imports": "in imports",
    "exports": "in exports",
    "pattern": "pattern to match with",
    "recursive": "be recursive"
  }, short={
    "authenticode": 'A',
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
  }]  
)