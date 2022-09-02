# Peni

Peni - your PE toolkit written in Nim.

**Warning: This project is still work in progress. Expect bugs.**

Peni is based on [nim-libpe](https://github.com/srozb/nim-libpe) - a Nim rewrite
of [merces/libpe](https://github.com/merces/libpe) library. It aims to remain
the same API but without using 3rd party dynlibs such as cygwin or openssl.
To stay as close as possible to the original library I had to use low-level 
unmanaged stuff so do expect bugs and crashes until the code is stabilized.

I created it because I really wanted to have tool allowing me to find files 
matching specified import/export pattern. Consult examples to get the idea.

## Showcase

## Features/examples

* Display comprehensive information regarding exe/dll `peni info -a [-r] <path>`
* Grep the directory looking for symbol matching given regex `peni grep -IE -p "pattern" -r C:\Windows\System32`
* List high entropy files within given directory `peni entropy -t 7.0 -r C:\Windows`
* Count some hashes `peni hash --ssdeep --sha256 -r C:\Windows\System32`

## Installation

1. Ensure Nim compiler is installed on your system
2. `nimble install peni` should do the trick

Alternatively you could download the precompiled binary.

## Usage

Peni is a multitool:

```
Usage:
  peni {SUBCMD}  [sub-command options & parameters]
where {SUBCMD} is one of:
  help     print comprehensive or per-cmd help
  info     Reads information about PE file.
  grep     Search files of given criteria
  hash     Calculate hash values.
  entropy  Calculate file entropy (only for PE files).

peni {-h|--help} or with no args at all prints this message.
peni --help-syntax gives general cligen syntax help.
Run "peni {help SUBCMD|SUBCMD --help}" to see help for just SUBCMD.
Run "peni help" to get *comprehensive* help.
```

You can use shorthands such as `peni i` instead of `peni info`. Only valid PE
file will be processed - other files are skipped.
