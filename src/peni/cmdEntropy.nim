import libpe
import strformat

import ctx

proc entropy*(threshold = 0.0, recursive = false, files: seq[string]) =
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    let ent = pe_calculate_entropy_file(addr ctx)
    if ent >= threshold:
      echo fmt"{ctx.path}:{ent}" 
