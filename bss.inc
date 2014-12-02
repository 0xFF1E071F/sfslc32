section .bss    
QueryOptions        resd 1
errno               resd 1

struc addrinfo
    .ai_flags       resd 1
    .ai_family      resd 1
    .ai_socktype    resd 1
    .ai_protocol    resd 1
    .ai_addrlen     resd 1
    .ai_addr        resd 1
    .ai_canonname   resd 1
    .ai_next        resd 1
    .size           equ $ - addrinfo
endstruc

hints       resb addrinfo.size
servinfo    resb addrinfo.size
;~ 
;~ servinfo:
    ;~ .ai_flags       resd 1
    ;~ .ai_family      resd 1
    ;~ .ai_socktype    resd 1
    ;~ .ai_protocol    resd 1
    ;~ .ai_addrlen     resd 1
    ;~ .ai_addr        resd 1
    ;~ .ai_canonname   resd 1
    ;~ .ai_next        resd 1
    ;~ .pad0           resq 1
    ;~ .pad1           resq 1
    ;~ .pad2           resq 1
        
pszSpammerInfo:
    .IP             resd 1
    .Name           resd 1
    .Email          resd 1
    .Evidence       resd 1
    .APIKey         resd 1
    .len            equ ($ - pszSpammerInfo) / 4 - 1

SFSReplyStruc:
    .Freq           resb 32
    .Conf           resb 16 
    .Seen           resb 32      


