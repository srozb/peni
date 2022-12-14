# Package

version       = "0.4.5"
author        = "srozb"
description   = "PE tool based on libpe (with no S)"
license       = "MIT"
srcDir        = "src"
binDir        = "release"
bin           = @["peni"]


# Dependencies

requires "nim >= 1.6.6, libpe >= 0.3.6, cligen >= 1.5.24, nancy >= 0.1.0, termstyle >= 0.1.0, authenticode >= 0.1.1, regex >= 0.20.0"
