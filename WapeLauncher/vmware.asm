.code

IsInsideVmWare proc

      push   rdx
      push   rcx
      push   rbx

      mov    rax, 'VMXh'
      mov    rbx, 0     ; any value but not the MAGIC VALUE
      mov    rcx, 10    ; get VMWare version
      mov    rdx, 'VX'  ; port number

      in     rax, dx    ; read port
                        ; on return EAX returns the VERSION
      cmp    rbx, 'VMXh'; is it a reply from VMWare?
      setz   al         ; set return value
      movzx  rax, al

      pop    rbx
      pop    rcx
      pop    rdx

      ret
IsInsideVmWare endp

END