import os
import libpe
import libpe/pe
import libpe/error

proc getCtx*(ctx: var pe_ctx_t, fn: string): bool =
  ## Reads and parses the filename as pe_ctx_t object.
  if pe_load_file(addr ctx, fn.cstring) != LIBPE_E_OK:
    discard pe_unload(addr ctx)
    return
  if pe_parse(addr ctx) != LIBPE_E_OK:
    discard pe_unload(addr ctx)
    return
  if not pe_is_pe(addr ctx):
    discard pe_unload(addr ctx)
    return
  return true

iterator peCtx*(files: seq[string], recursive = false): pe_ctx_t =
  ## Iterates over given files sequence and yields already parsed pe_ctx_t.
  ## This iterator skips files that are not valid PE.
  ## It will raise an exception only in case a single file was given and it's not valid.
  for path in files:
    var ctx: pe_ctx_t
    if path.fileExists:
      if not ctx.getCtx(path): raise newException(IOError, path & ": unable to read.")
      yield ctx
      discard pe_unload(addr ctx)
      continue
    if recursive:
      for fn in walkDirRec(path):
        try:
          if not ctx.getCtx(fn): continue
        except OSError:
          continue
        yield ctx
        discard pe_unload(addr ctx)
    else:
      for fn in walkFiles(path):
        try:
          if not ctx.getCtx(fn): continue
        except OSError:
          continue
        yield ctx
        discard pe_unload(addr ctx)