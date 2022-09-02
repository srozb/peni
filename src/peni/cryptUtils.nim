import libpe
import libpe/pe

proc genHash*(ctx: pe_ctx_t, hType: string): string =
  var hSize = pe_hash_recommended_size()
  var outString = newString(hSize)
  if pe_hash_raw_data(outString.cstring, hSize, hType.cstring, 
    cast[ptr uint8](ctx.map_addr), ctx.map_size.uint):
    result = outString
    result.setLen hSize
