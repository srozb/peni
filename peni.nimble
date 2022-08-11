# Package

version       = "0.1.0"
author        = "srozb"
description   = "PE toolkit based on libpe (with no S)"
license       = "MIT"
srcDir        = "src"
bin           = @["peni"]


# Dependencies

requires "nim >= 1.6.4, libpe >= 0.1.0, cligen >= 1.5.24, colorize >= 0.2.0"
