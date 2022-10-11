import libpe
import libpe/pe
import libpe/imports
import libpe/exports
import authenticode
import authenticode/parser
import strformat
import regex
import termstyle

import ctx

const COLOR = true

proc decoratePrint(filepath, category, buf: string, cPattern: Regex, offset: uint32=0) =
  if not buf.contains(cPattern): return
  let colOffset = if offset == 0: "" else: ',' & fmt"{offset:#x}".blue
  let colBuf = if COLOR == false: buf else: buf.replace(cPattern, "$1".red)
  echo fmt"{filepath}[{category.yellow}]{colOffset}:{colBuf}"

proc matchAuthenticode(ctx: var pe_ctx_t, cPattern: Regex) = 
  initialize_authenticode_parser()
  let sign = parse_authenticode(cast[ptr uint8](ctx.map_addr), ctx.map_size.uint)
  if sign.isNil: return  # No authenticode present
  for s in sign[].items:
      for signer in s.signer.chain[].items:
        decoratePrint($ctx.path, "signer issuer", $signer[].issuer, cPattern)
        decoratePrint($ctx.path, "signer subject", $signer[].subject, cPattern)
      for cert in s.certs[].items:
        decoratePrint($ctx.path, "cert issuer", $cert[].issuer, cPattern)
        decoratePrint($ctx.path, "cert subject", $cert[].subject, cPattern)
  authenticode_array_free(sign)

proc matchImports(ctx: var pe_ctx_t, cPattern: Regex) =
  for imp in pe_imports(addr ctx).items:
    for fun in imp.items:
      decoratePrint($ctx.path, "import", fmt"{imp.name}!{fun.name}", cPattern)

proc matchExports(ctx: var pe_ctx_t, cPattern: Regex) = 
  for exp in pe_exports(addr ctx).items:
    decoratePrint($ctx.path, "export", $exp.name, cPattern, exp.address)

proc grep*(ignoreCase = false, authenticode = false, imports = false, exports = false, pattern = "", 
  recursive = false, files: seq[string]) =
  ## Search files of given criteria
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    var flags = if ignoreCase: "(?i)" else: ""
    let cPattern = re(flags & "(" & pattern & ")")
    if imports: ctx.matchImports(cPattern)
    if exports: ctx.matchExports(cPattern)
    if authenticode: ctx.matchAuthenticode(cPattern)