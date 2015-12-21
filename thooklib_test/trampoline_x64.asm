.code

	mov r15,0x01
	cmp r15,0
	jnz reroute
	jmp 0x02
reroute:
	jmp 0x03
