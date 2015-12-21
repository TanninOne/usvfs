format PE GUI 4.0

include 'win32a.inc'
  invoke MessageBoxA,0,_bla,_cap,MB_ICONQUESTION+MB_YESNO
  CMP EAX, 0
  JZ CALL_REGULAR
  POP ECX
  MOV [EAX], ECX
  CALL 0xEEEEEEEE
  PUSH EAX
  CALL 0xBBBBBBBB
  POP ECX
  PUSH EAX
CALL_REGULAR:
  MOV EAX, ECX
  RETN

_bla db 'bla',0
_cap db 'cap',0

; import data in the same section

data import

 library kernel32,'KERNEL32.DLL',\
	 user32,'USER32.DLL',\
	 winmm,'WINMM.DLL'

 import kernel32,\
	ExitProcess,'ExitProcess'

 import user32,\
	MessageBoxA,'MessageBoxA'

 import winmm,\
	mciSendString,'mciSendStringA'

end data
