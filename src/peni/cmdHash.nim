import strformat
import libpe
import libpe/hashes

import ctx

proc genHash(ctx: pe_ctx_t, hType: string): string =
  let hSize = pe_hash_recommended_size()
  var output = newString(hSize)
  if pe_hash_raw_data(output.cstring, hSize, hType.cstring, 
    cast[ptr uint8](ctx.map_addr), ctx.map_size.uint):
    output.setLen(output.find('\0'))
    result = output

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