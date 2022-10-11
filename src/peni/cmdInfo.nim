import libpe
import libpe/pe
import libpe/hdr_optional
import libpe/imports
import libpe/exports
import libpe/hashes
import libpe/sections
import libpe/directories
import ctx
import output
import strformat
import strutils
import nancy
import termstyle
import times
import signatures/susp
import cryptUtils
import authenticode
import authenticode/parser

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
    sects.add sec[].getName()
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
    table.add "Subsystem required", fmt"{hOpt.CheckSum:#x}"
    table.add "Checksum", fmt"{hOpt.CheckSum:#x}"
    table.add "DLL characteristics", fmt"{hOpt.DllCharacteristics:#x}"
    table.add "DLL characteristics names", fmt"TODO"
    table.add "Size of stack to reserve", fmt"{hOpt.SizeOfStackReserve:#x}"
    table.add "Size of stack to commit", fmt"{hOpt.SizeOfStackCommit:#x}"
    table.add "Size of heap space to reserve", fmt"{hOpt.SizeOfHeapReserve:#x}"
    table.add "Size of heap space to commit", fmt"{hOpt.SizeOfHeapCommit:#x}"


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
  const validFlags = @[
    (IMAGE_SCN_CNT_CODE, "contains executable code"),
    (IMAGE_SCN_CNT_INITIALIZED_DATA, "contains initialized data"),
    (IMAGE_SCN_CNT_UNINITIALIZED_DATA, "contains uninitialized data"),
    (IMAGE_SCN_GPREL, "contains data referenced through the GP"),
    (IMAGE_SCN_LNK_NRELOC_OVFL, "contains extended relocations"),
    (IMAGE_SCN_MEM_DISCARDABLE, "can be discarded as needed"),
    (IMAGE_SCN_MEM_NOT_CACHED, "cannot be cached"),
    (IMAGE_SCN_MEM_NOT_PAGED, "is not pageable"),
    (IMAGE_SCN_MEM_SHARED, "can be shared in memory"),
    (IMAGE_SCN_MEM_EXECUTE, "is executable"),
    (IMAGE_SCN_MEM_READ, "is readable"),
    (IMAGE_SCN_MEM_WRITE, "is writable")
  ]
  for sec in ctx.sections:
    var charNames: string
    for flag in validFlags:
      if bool(sec.Characteristics and flag[0].uint32):
        charNames &= flag[1] & ", "
    withTable "Sections":
      table.add "Section Name", sec[].getName.bold
      table.add "Virtual Size", fmt"{sec.Misc.VirtualSize:#x}"
      table.add "Size Of Raw Data", fmt"{sec.SizeOfRawData:#x}"
      table.add "Pointer To Raw Data", fmt"{sec.PointerToRawData:#x}"
      table.add "Number Of Relocations", $sec.NumberOfRelocations
      table.add "Characteristics", fmt"{sec.Characteristics:#x}"
      table.add "Characteristics Names", charNames

proc printDirectories(ctx: var pe_ctx_t) =
  const dirNames = @[
    (IMAGE_DIRECTORY_ENTRY_EXPORT, "Export Table"),
    (IMAGE_DIRECTORY_ENTRY_IMPORT, "Import Table"),
    (IMAGE_DIRECTORY_ENTRY_RESOURCE, "Resource Table"),
    (IMAGE_DIRECTORY_ENTRY_EXCEPTION, "Exception Table"),
    (IMAGE_DIRECTORY_ENTRY_SECURITY, "Certificate Table"),
    (IMAGE_DIRECTORY_ENTRY_BASERELOC, "Base Relocation Table"),
    (IMAGE_DIRECTORY_ENTRY_DEBUG, "Debug"),
    (IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, "Architecture"),
    (IMAGE_DIRECTORY_ENTRY_GLOBALPTR, "Global Ptr"),
    (IMAGE_DIRECTORY_ENTRY_TLS, "Thread Local Storage (TLS)"),
    (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "Load Config Table"),
    (IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, "Bound Import"),
    (IMAGE_DIRECTORY_ENTRY_IAT, "Import Address Table (IAT)"),
    (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, "Delay Import Descriptor"),
    (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, "CLR Runtime Header"),
    (IMAGE_DIRECTORY_RESERVED, "")
  ]
  proc resolve(i: ImageDirectoryEntry): string =
    for (dn, descr) in dirNames:
      if dn == i: return descr
  withTable "Directories":
    table.add "Directory Name", "Virtual Address", "Size"
    for dirType, dirVal in ctx.directories:
      table.add resolve(dirType), fmt"{dirVal.VirtualAddress:#x}", $dirVal.Size

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

proc toTable(c: Certificate, t: var TerminalTable) =
  t.add "Version", $c.version
  t.add "Issuer", $c.issuer
  t.add "Subject", $c.subject
  t.add "Serial", $c.serial
  t.add "SHA1", $c.sha1
  t.add "SHA256", $c.sha256
  t.add "Sign. algorithm", $c.sig_alg
  t.add "Sign. algorithm OID", $c.sig_alg_oid
  t.add "Not Before", $fromUnix(cast[int64](c.not_before)).utc
  t.add "Not After", $fromUnix(cast[int64](c.not_after)).utc
  t.add "Key algorithm", $c.key_alg
  t.add "Key", $c.key

proc printAuthenticode(ctx: var pe_ctx_t) =
  initialize_authenticode_parser()
  let sign = parse_authenticode(cast[ptr uint8](ctx.map_addr), ctx.map_size.uint)
  if sign.isNil: return  # No authenticode present
  var i,j,k = 0
  for s in sign[].items:
    i.inc
    withTable fmt"Signature #{i}":
      table.add "Version", $s[].version
      table.add "Digest Algorithm", $s[].digest_alg
      table.add "Digest", $s[].digest
      for signer in s.signer.chain[].items:
        j.inc
        table.add fmt"Signer #{j}".bold
        signer[].toTable(table)
      j = 0
      for cert in s.certs[].items:
        k.inc
        table.add fmt"Cert #{k}".bold
        cert[].toTable(table)
      k = 0
  authenticode_array_free(sign)

proc info*(all = false, summary = true, headers = false, sections = false, 
  directories = false, imports = false, exports = false, authenticode = false, 
  recursive = false, files: seq[string]) =
  ## Show PE file details.
  for c in files.peCtx(recursive=recursive):
    var ctx = c
    echo fmt"{ctx.path}:".magenta.bold
    if all or summary: printSummary(ctx)
    if all or headers: printHeaders(ctx)
    if all or sections: printSections(ctx)
    if all or directories: printDirectories(ctx)
    if all or imports: printImports(ctx)
    if all or exports: printExports(ctx)
    if all or authenticode: printAuthenticode(ctx)
