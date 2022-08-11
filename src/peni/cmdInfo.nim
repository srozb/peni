import libpe
import ctx

proc printSummary(ctx: pe_ctx_t) =
  discard
proc printHeaders(ctx: pe_ctx_t) =
  discard
proc printSections(ctx: pe_ctx_t) =
  discard
proc printDirectories(ctx: pe_ctx_t) =
  discard
proc printImports(ctx: pe_ctx_t) =
  discard
proc printExports(ctx: pe_ctx_t) =
  discard

proc info*(all = false, summary = true, headers = false, sections = false, 
  directories = false, imports = false, exports = false, recursive = false,
  files: seq[string]) =
  ## Reads information about PE file.
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    if all or summary: printSummary(ctx)
    if all or headers: printHeaders(ctx)
    if all or sections: printSections(ctx)
    if all or directories: printDirectories(ctx)
    if all or sections: printImports(ctx)
    if all or sections: printExports(ctx)
