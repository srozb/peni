import libpe
import ctx
import strformat
import strutils
import nancy
import termstyle

proc getFilename(ctx: var pe_ctx_t): string {.inline.} =
  result = $ctx.path
  when defined windows:
    let pathSep = '\\'
  else:
    let pathSep = '/'
  if result.rsplit(pathSep, 1).len == 2:
    result = result.rsplit(pathSep, 1)[1]

proc getHeaderType(ctx: var pe_ctx_t): string {.inline.} =
  result = "Unknown".red
  if ctx.pe.optional_hdr.`type` == 0x20b: result = "PE32+ (x64)"
  elif  ctx.pe.optional_hdr.`type` == 0x10b: result = "PE32 (x86)"

proc printSummary(ctx: var pe_ctx_t) =
  ## Print Summary
  ## TODO: packer detection
  var table: TerminalTable
  table.add "File Name", ctx.getFilename  # TODO: extract filename
  table.add "File Size", $ctx.map_size & " bytes"
  table.add "Is DLL?", fmt"{pe_is_dll(addr ctx)}"
  table.add "Header", getHeaderType(ctx)
  table.add "Entrypoint", fmt"{ctx.pe.entrypoint:#x}"
  table.add "Sections", fmt"{pe_sections_count(addr ctx)}"
  table.add "Directories", fmt"{pe_directories_count(addr ctx)}"
  table.echoTable(80, padding = 4)
  echo ""
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
    echo fmt"  {ctx.path}:".magenta
    if all or summary: printSummary(ctx)
    if all or headers: printHeaders(ctx)
    if all or sections: printSections(ctx)
    if all or directories: printDirectories(ctx)
    if all or sections: printImports(ctx)
    if all or sections: printExports(ctx)
