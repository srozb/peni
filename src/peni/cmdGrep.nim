import libpe
import libpe/imports
import libpe/exports
import strformat
import strutils

import ctx

proc matchImports(ctx: var pe_ctx_t, fn: string, pattern: string) =
  for imp in pe_imports(addr ctx).items:
    for fun in imp.items:
      let qName = fmt"{imp.name}!{fun.name}"
      if pattern == "" or pattern.toLower in qName.toLower:
        echo fmt"{fn}:{qName} (import)"

proc matchExports(ctx: var pe_ctx_t, fn: string, pattern: string) = 
  for exp in pe_exports(addr ctx).items:
    if pattern == "" or pattern.toLower in ($exp.name).toLower:
      echo fmt"{fn},{exp.address:#x}:{exp.name} (export)"

proc grep*(imports = false, exports = false, pattern = "", recursive = false, files: seq[string]) =
  ## Search files of given criteria
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    if imports: ctx.matchImports($ctx.path, pattern)
    if exports: ctx.matchExports($ctx.path, pattern)