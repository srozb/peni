import libpe
import libpe/hdr_optional
import ctx
import strformat
import strutils
import nancy
import termstyle
import times

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
  table.add "File Name", ctx.getFilename
  table.add "File Size", $ctx.map_size & " bytes"
  table.add "Is DLL?", fmt"{pe_is_dll(addr ctx)}"
  table.add "Header", getHeaderType(ctx)
  table.add "Entrypoint", fmt"{ctx.pe.entrypoint:#x}"
  table.add "Sections", fmt"{pe_sections_count(addr ctx)}"
  table.add "Directories", fmt"{pe_directories_count(addr ctx)}"
  table.echoTable(80, padding = 4)
  echo ""

proc printDosHeader(ctx: var pe_ctx_t) =
  var table: TerminalTable
  let hDos = pe_dos(addr ctx)
  table.add "Dos Header".bold
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
  table.echoTable(80, padding = 4)
  echo ""

proc printCoffHeader(ctx: var pe_ctx_t) =
  var table: TerminalTable
  let hCoff = pe_coff(addr ctx)
  let tStamp = fromUnix(hCoff.TimeDateStamp.int64).utc  # TODO: Check if correct
  table.add "COFF/File header".bold
  table.add "Machine", fmt"{hCoff.Machine:#x}"  # TODO: machineTypeTable
  table.add "Number of sections", $hCoff.NumberOfSections
  table.add "Date/time stamp", $tStamp
  table.add "Symbol Table offset", fmt"{hCoff.PointerToSymbolTable:#x}"
  table.add "Number of symbols", $hCoff.NumberOfSymbols
  table.add "Size of optional header", fmt"{hCoff.SizeOfOptionalHeader:#x}"
  table.add "Characteristics", fmt"{hCoff.Characteristics:#x}"
  table.add "Characteristics names", "TODO"
  table.echoTable(80, padding = 4)
  echo ""

proc printOptionalHeaderValues[T](hOpt: T) =
  var table: TerminalTable
  table.add "Optional/Image header".bold
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
  table.echoTable(80, padding = 4)
  echo ""

proc printOptionalHeader(ctx: var pe_ctx_t) =
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
    var table: TerminalTable
    table.add "Section Name".bold, $sec.Name.bold
    table.add "Virtual Size", fmt"{sec.Misc.VirtualSize:#x}"
    table.add "Size Of Raw Data", fmt"{sec.SizeOfRawData:#x}"
    table.add "Pointer To Raw Data", fmt"{sec.PointerToRawData:#x}"
    table.add "Number Of Relocations", $sec.NumberOfRelocations
    table.add "Characteristics", fmt"{sec.Characteristics:#x}"
    table.add "Characteristics Names", "TODO"
    table.echoTable(80, padding = 4)
    echo ""

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
    echo fmt"{ctx.path}:".magenta.bold
    if all or summary: printSummary(ctx)
    if all or headers: printHeaders(ctx)
    if all or sections: printSections(ctx)
    if all or directories: printDirectories(ctx)
    if all or sections: printImports(ctx)
    if all or sections: printExports(ctx)
