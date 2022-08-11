import strformat
import libpe
import libpe/hashes

import ctx

proc hash*(imphash = false, md5 = false, sha1 = false, sha256 = false, 
  ssdeep = false, recursive = false, files: seq[string]) =
  ## Calculate hash values.
  for c in files.peCtx(recursive=recursive):
    var ctx = c    
    let all = not (imphash or md5 or sha1 or sha256 or ssdeep)
    if all or imphash: echo fmt"{ctx.path},imphash:{pe_imphash(addr ctx, LIBPE_IMPHASH_FLAVOR_PEFILE)}" 
