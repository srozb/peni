import strutils
import cligen

import peni/cmdInfo
import peni/cmdHash
import peni/cmdGrep
import peni/cmdEntropy


dispatchMulti(
    [info, short = {
      "headers": 'H',
      "sections": 'S'
    }
    ],
    [grep, help={
      "imports": "in imports",
      "exports": "in exports",
      "pattern": "pattern to match with"
    }, short={
      "imports": 'I',
      "exports": 'E'
    }],
    [hash, short={
      "sha256": 'S',
      "ssdeep": 'd'
    }],
    [entropy]
  )