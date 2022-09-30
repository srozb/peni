# Package

version       = "0.3.3"
author        = "srozb"
description   = "PE tool based on libpe (with no S)"
license       = "MIT"
srcDir        = "src"
bin           = @["peni"]


# Dependencies

requires "nim >= 1.6.4, libpe >= 0.3.3, cligen >= 1.5.24, nancy >= 0.1.0, termstyle >= 0.1.0, flower >= 0.1.0, flatty >= 0.3.4"
