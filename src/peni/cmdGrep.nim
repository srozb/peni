import libpe
import libpe/pe
import libpe/imports
import libpe/exports
import strformat
import regex
import termstyle

import ctx

const COLOR = true

proc matchImports(ctx: var pe_ctx_t, cPattern: Regex) =
  for imp in pe_imports(addr ctx).items:
    for fun in imp.items:
      let qName = fmt"{imp.name}!{fun.name}"
      if qName.contains(cPattern):
        var msg = fmt"{ctx.path}:{qName} (import)"
        if COLOR: msg = msg.replace(cPattern, "$1".red)
        echo msg

proc matchExports(ctx: var pe_ctx_t, cPattern: Regex) = 
  for exp in pe_exports(addr ctx).items:
    if ($exp.name).contains(cPattern):
      var msg = fmt"{ctx.path}," & fmt"{exp.address:#x}".blue & fmt":{exp.name} (export)"
      if COLOR: msg = msg.replace(cPattern, "$1".red)
      echo msg

proc grep*(ignoreCase = false, imports = false, exports = false, pattern = "", 
  recursive = false, files: seq[string]) =
  ## Search files of given criteria
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    var flags = if ignoreCase: "(?i)" else: ""
    let cPattern = re(flags & "(" & pattern & ")")
    if imports: ctx.matchImports(cPattern)
    if exports: ctx.matchExports(cPattern)