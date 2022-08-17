import strformat
import libpe
import libpe/hashes

import ctx
import cryptUtils

proc hash*(imphash = false, md5 = false, sha1 = false, sha256 = false, 
  ssdeep = false, recursive = false, files: seq[string]) =
  ## Calculate hash values.
  for c in files.peCtx(recursive=recursive):
    var ctx = c    
    let all = not (imphash or md5 or sha1 or sha256 or ssdeep)
    if all or imphash: echo fmt"{ctx.path},imphash:{pe_imphash(addr ctx, LIBPE_IMPHASH_FLAVOR_PEFILE)}" 
    if all or md5: echo fmt"""{ctx.path},md5:{ctx.genHash("md5")}"""  ## TODO: Template/Macro
    if all or sha1: echo fmt"""{ctx.path},sha1:{ctx.genHash("sha1")}"""
    if all or sha256: echo fmt"""{ctx.path},sha256:{ctx.genHash("sha256")}"""
    if all or ssdeep: echo fmt"""{ctx.path},ssdeep:{ctx.genHash("ssdeep")}"""