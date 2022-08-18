import nancy
import termstyle

template withTable*(caption: string, body: untyped) = 
  var table {.inject.}: TerminalTable
  if caption.len > 0: table.add caption.bold
  body
  table.echoTable(80, padding = 4)
  echo ""