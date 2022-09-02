import libpe
import libpe/pe
import libpe/hdr_optional
import libpe/imports
import libpe/exports
import libpe/hashes
import ctx
import output
import strformat
import strutils
import nancy
import termstyle
import times
import signatures/susp
import cryptUtils

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

proc getCompileTime(ctx: var pe_ctx_t): string {.inline.} =
  result = $fromUnix(pe_coff(addr ctx).TimeDateStamp.int64).utc

proc getColoredEntropy(ctx: var pe_ctx_t): string {.inline.} =
  let ent = pe_calculate_entropy_file(addr ctx)
  result = $ent.green
  if ent > 7.5:
    result = $ent.red
  elif ent > 6.5:
    result = $ent.yellow

proc getSignature(ctx: var pe_ctx_t): string {.inline.} =
  result = "-"
  for dirType, dirVal in ctx.directories:
    if dirType.int == 4 and dirVal.Size > 0:  # 4 -> IMAGE_DIRECTORY_ENTRY_SECURITY
      return fmt"Present (unverified) @ {dirVal.VirtualAddress:#x}".yellow

proc printSummary(ctx: var pe_ctx_t) =
  ## Print Summary
  ## TODO: packer detection
  var dirs: seq[string]
  var sects: seq[string]
  for dirType, _ in ctx.directories:
    dirs.add $pe_directory_name(dirType)
  for sec in ctx.sections:
    sects.add $sec.Name
  withTable "":
    table.add "File Name", ctx.getFilename
    table.add "File Size", $ctx.map_size & " bytes"
    table.add "Compile Time", getCompileTime(ctx)
    table.add "Is DLL?", fmt"{pe_is_dll(addr ctx)}"
    table.add "Header", getHeaderType(ctx)
    table.add "Entrypoint", fmt"{ctx.pe.entrypoint:#x}"
    table.add "Sections", sects.join(" ")
    table.add "Directories", dirs.join(" ")
    table.add "File Entropy", getColoredEntropy(ctx)
    table.add "MD5", ctx.genHash("md5")
    table.add "SHA1", ctx.genHash("sha1")
    table.add "SHA256", ctx.genHash("sha256")
    table.add "SSDEEP", ctx.genHash("ssdeep")
    table.add "Imphash", $pe_imphash(addr ctx, LIBPE_IMPHASH_FLAVOR_PEFILE)
    table.add "Signature", getSignature(ctx)


proc printDosHeader(ctx: var pe_ctx_t) =
  let hDos = pe_dos(addr ctx)
  withTable "Dos Header":
    table.add "Magic Number", fmt"{hDos.e_magic:#x}"
    table.add "Bytes in last page", $hDos.e_cblp
    table.add "Pages in file", $hDos.e_cp
    table.add "Relocations", $hDos.e_crlc
    table.add "Size of header in paragraphs", $hDos.e_cparhdr
    table.add "Minimum extra paragraphs", $hDos.e_minalloc
    table.add "Maximum extra paragraphs", $hDos.e_maxalloc
    table.add "Initial (relative) SS value", fmt"{hDos.e_ss:#x}"
    table.add "Initial SP value", fmt"{hDos.e_sp:#x}"
    table.add "Initial IP value", fmt"{hDos.e_ip:#x}"
    table.add "Initial (relative) CS value", fmt"{hDos.e_cs:#x}"
    table.add "Address of relocation table", fmt"{hDos.e_lfarlc:#x}"
    table.add "Overlay number", fmt"{hDos.e_ovno:#x}"
    table.add "OEM identifier", fmt"{hDos.e_oemid:#x}"
    table.add "OEM information", fmt"{hDos.e_oeminfo:#x}"
    table.add "PE header offset", fmt"{hDos.e_lfanew:#x}"

proc printCoffHeader(ctx: var pe_ctx_t) =
  let 
    hCoff = pe_coff(addr ctx)
    tStamp = fromUnix(hCoff.TimeDateStamp.int64).utc  # TODO: Check if correct
  withTable "COFF/File header":
    table.add "Machine", fmt"{hCoff.Machine:#x}"  # TODO: machineTypeTable
    table.add "Number of sections", $hCoff.NumberOfSections
    table.add "Date/time stamp", $tStamp
    table.add "Symbol Table offset", fmt"{hCoff.PointerToSymbolTable:#x}"
    table.add "Number of symbols", $hCoff.NumberOfSymbols
    table.add "Size of optional header", fmt"{hCoff.SizeOfOptionalHeader:#x}"
    table.add "Characteristics", fmt"{hCoff.Characteristics:#x}"
    table.add "Characteristics names", "TODO"

proc printOptionalHeaderValues[T: ptr IMAGE_OPTIONAL_HEADER_32 | ptr IMAGE_OPTIONAL_HEADER_64](hOpt: T) =
  withTable "Optional/Image header":
    table.add "Magic number", fmt"{hOpt.Magic:#x}"
    table.add "Linker major version", $hOpt.MajorLinkerVersion
    table.add "Linker minor version", $hOpt.MinorLinkerVersion
    table.add "Size of .text section", fmt"{hOpt.SizeOfCode:#x}"
    table.add "Size of .data section", fmt"{hOpt.SizeOfInitializedData:#x}"
    table.add "Size of .bss section", fmt"{hOpt.SizeOfUninitializedData:#x}"
    table.add "Entrypoint", fmt"{hOpt.AddressOfEntryPoint:#x}"
    table.add "Address of .text section", fmt"{hOpt.BaseOfCode:#x}"
    when typeof(hOpt) is typeof(ptr IMAGE_OPTIONAL_HEADER_32):
      table.add "Address of .data section", fmt"{hOpt.BaseOfData:#x}"
    table.add "ImageBase", fmt"{hOpt.ImageBase:#x}"
    table.add "Alignment of sections", fmt"{hOpt.SectionAlignment:#x}"
    table.add "Alignment factor", fmt"{hOpt.FileAlignment:#x}"
    table.add "Major version of required OS", $hOpt.MajorOperatingSystemVersion
    table.add "Minor version of required OS", $hOpt.MinorOperatingSystemVersion
    table.add "Major version of image", $hOpt.MajorImageVersion
    table.add "Minor version of image", $hOpt.MinorImageVersion
    table.add "Major version of subsystem", $hOpt.MajorSubsystemVersion
    table.add "Minor version of subsystem", $hOpt.MinorSubsystemVersion
    table.add "Size of image", fmt"{hOpt.SizeOfImage:#x}"
    table.add "Size of headers", fmt"{hOpt.SizeOfHeaders:#x}"
    table.add "Checksum", fmt"{hOpt.CheckSum:#x}"

proc printOptionalHeader(ctx: var pe_ctx_t) =  # TODO: cleanup
  let hOpt = pe_optional(addr ctx)
  case hOpt.`type`:
    of 0x10b:  # PE32
      printOptionalHeaderValues(hOpt.h_32)
    else:  # 0x20b - PE32+
      printOptionalHeaderValues(hOpt.h_64)

proc printHeaders(ctx: var pe_ctx_t) =
  printDosHeader(ctx)
  printCoffHeader(ctx)
  printOptionalHeader(ctx)

proc printSections(ctx: var pe_ctx_t) =
  for sec in ctx.sections:
    withTable "Sections":
      table.add "Section Name", $sec.Name.bold
      table.add "Virtual Size", fmt"{sec.Misc.VirtualSize:#x}"
      table.add "Size Of Raw Data", fmt"{sec.SizeOfRawData:#x}"
      table.add "Pointer To Raw Data", fmt"{sec.PointerToRawData:#x}"
      table.add "Number Of Relocations", $sec.NumberOfRelocations
      table.add "Characteristics", fmt"{sec.Characteristics:#x}"
      table.add "Characteristics Names", "TODO"

proc printDirectories(ctx: var pe_ctx_t) =
  withTable "Directories":
    table.add "Directory Name", "Virtual Address", "Size"
    for dirType, dirVal in ctx.directories:
      table.add $pe_directory_name(dirType), fmt"{dirVal.VirtualAddress:#x}", $dirVal.Size

proc printImports(ctx: var pe_ctx_t) =
  withTable "Imported Functions":
    table.add "Library", "Function", "Hint"
    for lib in pe_imports(addr ctx).items:
      for fun in lib.items:
        if $fun.name in suspImports: table.add $lib.name.yellow, $fun.name.yellow, $fun.hint.yellow
        else:  table.add $lib.name, $fun.name, $fun.hint

proc printExports(ctx: var pe_ctx_t) =
  let exps = pe_exports(addr ctx)
  withTable "Exported Functions":
    table.add "Library", "Function", "Fwd Name", "Address", "Ordinal"
    for exp in exps.items:
      if $exp.name in suspExports or $exp.fwd_name in suspExports:
        table.add $exps.name.yellow, $exp.name.yellow, $exp.fwd_name.yellow, fmt"{exp.address:#x}".yellow, $exp.ordinal.yellow
      else:
        table.add $exps.name, $exp.name, $exp.fwd_name, fmt"{exp.address:#x}", $exp.ordinal

proc info*(all = false, summary = true, headers = false, sections = false, 
  directories = false, imports = false, exports = false, recursive = false,
  files: seq[string]) =
  ## Reads information about PE file.
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    echo fmt"{ctx.path}:".magenta.bold
    if all or summary: printSummary(ctx)
    if all or headers: printHeaders(ctx)
    if all or sections: printSections(ctx)
    if all or directories: printDirectories(ctx)
    if all or imports: printImports(ctx)
    if all or exports: printExports(ctx)
