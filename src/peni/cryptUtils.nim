import libpe

proc genHash*(ctx: pe_ctx_t, hType: string): string =
  let hSize = pe_hash_recommended_size()
  var output = newString(hSize)
  if pe_hash_raw_data(output.cstring, hSize, hType.cstring, 
    cast[ptr uint8](ctx.map_addr), ctx.map_size.uint):
    output.setLen(output.find('\0'))
    result = output