import libpe
import libpe/imports
import libpe/exports
import strformat
import strutils
import std/re

import ctx

proc matchImports(ctx: var pe_ctx_t, cPattern: Regex, ignoreCase: bool) =
  for imp in pe_imports(addr ctx).items:
    for fun in imp.items:
      let qName = fmt"{imp.name}!{fun.name}"
      if qName.contains(cPattern):
        echo fmt"{ctx.path}:{qName} (import)"

proc matchExports(ctx: var pe_ctx_t, cPattern: Regex, ignoreCase: bool) = 
  for exp in pe_exports(addr ctx).items:
    if ($exp.name).contains(cPattern):
      echo fmt"{ctx.path},{exp.address:#x}:{exp.name} (export)"

proc grep*(ignoreCase = false, imports = false, exports = false, pattern = "", 
  recursive = false, files: seq[string]) =
  ## Search files of given criteria
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    var flags = {reStudy, reExtended}
    if ignoreCase: flags.incl(reIgnoreCase)
    let cPattern = pattern.re(flags)
    if imports: ctx.matchImports(cPattern, ignoreCase)
    if exports: ctx.matchExports(cPattern, ignoreCase)