import os
import libpe
import libpe/error

proc getCtx*(ctx: var pe_ctx_t, fn: string): bool =
  ## Reads and parses the filename as pe_ctx_t object.
  if pe_load_file(addr ctx, fn.cstring) != LIBPE_E_OK:
    return
  if pe_parse(addr ctx) != LIBPE_E_OK:
    return
  if not pe_is_pe(addr ctx):
    return
  return true

iterator peCtx*(files: seq[string], recursive = false): pe_ctx_t =
  ## Iterates over given files sequence and yields already parsed pe_ctx_t.
  for path in files:
    var ctx: pe_ctx_t
    if path.fileExists:
      if not getCtx(ctx, path): raise newException(IOError, path & ": unable to read.")
      yield ctx
      continue
    if recursive:
      for fn in walkDirRec(path):
        if not getCtx(ctx, fn): continue
        yield ctx
    else:
      for fn in walkFiles(path):
        if not getCtx(ctx, fn): continue
        yield ctx
    discard pe_unload(addr ctx)