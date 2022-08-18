switch("cincludes", gorgeEx("nimble path libpe").output & "/libpe/libpe/include/libpe")
when defined(mingw):
  discard
  #switch("passL", "-shared -l:libpe.dll")
else:
  switch("passL", "-lpe")

