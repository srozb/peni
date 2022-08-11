import strutils
import cligen

import peni/cmdInfo
import peni/cmdHash
import peni/cmdGrep
import peni/cmdEntropy


dispatchMulti(
    [info],
    [grep, help={
      "imports": "in imports",
      "exports": "in exports",
      "pattern": "pattern to match with"
    }],
    [hash],
    [entropy]
  )