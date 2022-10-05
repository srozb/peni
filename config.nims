import strutils
switch("cincludes", gorgeEx("nimble path libpe").output.strip & "/libpe/libpe/include/libpe")
switch("cincludes", gorgeEx("nimble path authenticode").output.strip & "/authenticode/src")
switch("passL", "-lcrypto")
when defined(MacOsX):
  switch("passl", "-L/usr/local/opt/openssl@1.1/lib")
  switch("cincludes", "/usr/local/opt/openssl@1.1/include")  # required by github macos runner
elif defined(Windows):
  switch("passl", "-LC:\\Progra~1\\OpenSSL-Win64\\lib")
  switch("cincludes", "C:\\Program Files\\OpenSSL-Win64\\include")