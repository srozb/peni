import flower
import flatty

import ctx
import cryptUtils

const 
  DEFSIZE = 1_000_000
  NSRLSIZE = 50_000_000

proc exportFlatty(b: Bloom, dstPath: string) = dstPath.writeFile(toFlatty(b))

# proc importFlatty*(srcPath: string): Bloom =
#   result = srcPath.readFile().fromFlatty(Bloom)

proc load*(srcPath: string): Bloom =
  discard

proc inBaseline*(sha1sum: string, b: Bloom): bool =
  return sha1sum in b

proc baseline*(baselineFile: string, bloomSize = DEFSIZE.int, errorRate = 0.001, 
    nsrl = false, recursive = false, files: seq[string]) =
  ## Create hash baseline and save as bloom filter
  let filterSize = (if nsrl and bloomSize == DEFSIZE: NSRLSIZE else: bloomSize)
  var 
    hashBloom = newBloom(filterSize, errorRate)
    processed = 0
  if nsrl:
    for src in files:  # TODO multifile support
      for l in src.lines():
        processed.inc
        if processed == 1: continue  # assuming csv header
        hashBloom.add(l[1..40])
      processed.dec
  else:
    for c in files.peCtx(recursive=recursive):
      var ctx = c
      hashBloom.add(ctx.genHash("sha1"))
      processed.inc
  echo $processed & " hashes processed."
  if processed > filterSize: echo "Too many hashes added - FP rate will increase."
  hashBloom.exportFlatty(baselineFile)
