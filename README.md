A Dll to load custom shellcode.

Tech:
  + Use AES to encrypt/decrypt the shellcode.
  + Unhook WinAPI function (userland).
  + Use HellGate for Direct Syscall (bypass the hook).
  + IAT Camouflage
