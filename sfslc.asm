 
%include '../../include/syscalls32.inc'
%include '../../include/socket.inc'
%include 'externs.inc'
%include 'equates.inc'
%include 'rodata.inc'
%include 'bss.inc'


global main

section .text
main:
    push    ebp
    mov     ebp, esp
    sub     esp, 4
    
    cmp     dword [ebp + 8], 1              ; check if we have more than 1 arg
    je      .help                           ; 1 = no args
    
.Args:           
    mov     eax, [ebp + 12]                 ; argv
    mov     ecx, [ebp + 8]                  ; argc
    push    NULL
    push    long_options 
    push    szArgs    
    push    eax
    push    ecx
    call    getopt_long_only 
    add     esp, 4 * 5
    test    eax, eax
    js      Continue    
    
    cmp     eax, "?"                        
    je      Done    
    
    jmp     [JumpTable + 4 * eax]
    
    
;*******************************************
.help:    
    push    szHelpString                    ; print help string
    call    PrintString    
    jmp     Done                            ; and quit program
    

;*******************************************    
.version:
    push    szVersion                       ; print version string
    call    PrintString
    jmp     Done                            ; and quit program

;*******************************************
.ip:
    test    dword [QueryOptions], OPT_IP    ; already have IP arg?
    jnz     .Args                           ; yes, get next arg
        
    lea     edx, [ebp - 4]                  ; check to see if valid IP entered   
    push    edx
    push    dword [optarg]                        ; 
    push    AF_INET                         ; 
    call    inet_pton                       ; 
    add     esp, 4 * 3
    test    eax, eax                        ; 
    jnz     .GoodIP                         ; yes it was
    
    ; invalid IP entered
    push    szErrInvalidIP                  ; err msg
    push    dword [optarg]                        ; entered IP 
    push    fmtstr2                         ;  
    call    printf                          ; print error msg
    add     esp, 4 * 3
    jmp     Done                            ; quit program
    
.GoodIP:  
    push    16                              ; create 16 byte buffer to hold IP
    call    malloc                          ; 
    add     esp, 4 * 1
    mov     [pszSpammerInfo.IP], eax        ; save pointer to IP buffer in struct
    
    push    dword [optarg]
    push    eax
    call    strcpy                          ; copy IP to buffer
    add     esp, 4 * 2
    or      dword [QueryOptions], OPT_IP    ; set IP bit flag TRUE
    jmp     .Args                           ; get next arg
    
;*******************************************
.email:
    test    dword [QueryOptions], OPT_EMAIL ; already have email arg?
    jnz     .Args                            ; yes, get next arg
    
    push    dword [optarg]                        ; 
    call    strlen                          ; get length of email
    add     esp, 4 * 1
    cmp     eax, MAX_EMAIL_LEN              ; 
    jle     .GoodEmailLen                   ; valid length
    
    push    szErrInvalidEmailLen            ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
    
.GoodEmailLen:
    lea     eax, [eax * 3 + 1]              ; email len * 3 + 1 for the NULL terminator
    push    eax
    call    malloc                          ; create buffer to hold encoded email
    add     esp, 4 * 1
    mov     [pszSpammerInfo.Email], eax     ; save pointer email buffer in struct

    push    dword [optarg]                        ; email address
    push    eax                             ; buffer to hold encoded email
    call    Encode                          ; URL encode email
    or      dword [QueryOptions], OPT_EMAIL ; set Email bit flag TRUE
    jmp     .Args

;*******************************************
.name:
    test    dword [QueryOptions], OPT_NAME  ; already have a username?
    jnz     .Args                            ; yes, get next arg
    
    push    dword [optarg]                        ; 
    call    strlen                          ; get length of username
    cmp     eax, MAX_NAME_LEN               ;
    jle     .GoodNameLen                    ; valid length

    push    szErrInvalidNameLen             ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
    
.GoodNameLen:
    lea     eax, [eax * 3 + 1]              ; name len * 3 + 1 for the NULL terminator
    push    eax
    call    malloc                          ; create buffer to hold encoded name
    add     esp, 4 * 1
    mov     [pszSpammerInfo.Name], eax      ; save pointer name buffer in struct

    push    dword [optarg]                        ; name 
    push    eax                             ; buffer to hold encoded name
    call    Encode                          ; URL encode name
    or      dword [QueryOptions], OPT_NAME  ; set Name bit flag TRUE
    jmp     .Args

;*******************************************
.apikey:
    test    dword [QueryOptions], OPT_API_KEY ; already have API key?
    jnz     .Args                           ; yup, get next arg
    
    push    eax                             ; Save option.val
    
    push    dword [optarg]                        ; 
    call    strlen                          ; make sure we have a valid key length
    add     esp, 4 * 1
    cmp     eax, 14                         ; only 14 chars is valid
    je    .GoodKeyLen                       ; good to go

    pop     eax                             ; balance stack, don't care about .val
    
    push    szErrInvalidKeyLen              ; display error msg
    call    PrintString
    jmp     Done                            ; and exit program
        
.GoodKeyLen:
    mov     edi, eax                        ; get length of api key
    pop     eax                             ; restore option.val
    or      dword [QueryOptions], OPT_API_KEY; set out bitmask
    
    add     edi, 1
    push    edi
    call    malloc                          ; create buffer to hold api key
    add     esp, 4 * 1
    mov     [pszSpammerInfo.APIKey], eax
    
    push    dword [optarg]                        ; api key arg string
    push    eax                             ; our buffer
    call    strcpy                          ; copy on over
    jmp     .Args

;*******************************************
.evidence:
    test    dword [QueryOptions], OPT_EVIDENCE
    jnz      .Args
         
    push    dword [optarg]
    call    strlen
    add     esp, 4 * 1
    test    eax, eax
    jz     .Args
    
.HaveEvidence:    
    lea     eax, [eax * 3 + 1]
    push    eax
    call    malloc
    add     esp, 4 * 1
    mov     [pszSpammerInfo.Evidence], eax
    
    push    dword [optarg]
    push    eax
    call    Encode

    or      dword [QueryOptions], OPT_EVIDENCE
    jmp     .Args
    
;*******************************************
.setwildcards:
    mov     eax, dword [OptionsBitmasks + 4 * eax]
    or      dword [QueryOptions], eax
    jmp     .Args

Done:
    mov     esi, pszSpammerInfo
    lea     ebx, [pszSpammerInfo.len]
.FreeSpammerInfo:
    push    dword [esi + 4 * ebx]
    call    free
    add     esp, 4 * 1
    sub     ebx, 1
    jns     .FreeSpammerInfo    
    
    call    exit    

;###########################################    
Continue:   
    call    __errno_location
    mov     [errno], eax
              
    test    dword [QueryOptions], OPT_QUERY ; check to see if query bitmask is set
    jnz     .PreQuery                       ; if !0, then do query
    
    test    dword [QueryOptions], OPT_SUBMIT; check to see if submit bitmask is set
    jnz      .CheckForKey                   ; if 0, then no submit

    push    szErrNoOptions
    call    PrintString
    jmp     Done
    
.CheckForKey:
    test    dword [QueryOptions], OPT_API_KEY; make sure we have API Key
    jnz     .PreSubmit
    
    ; no api key, display error and run far away
    push    szErrNeedKey
    call    PrintString
    jmp     Done  
 
.PreSubmit:
    ; To submit, 3 items are required, IP, Username, and email
    mov     eax, dword [QueryOptions]
    and     eax, 0111b
    cmp     eax, 0111b                      ; make sure we have all 3 bitmasks set
    je      .DoSubmit                       ; Phew, we got em!
    
    push    szErrNeed3
    call    PrintString
    jmp     Done 
    
.DoSubmit:
    call    SubmitStopFourmSpam
    jmp     Done
    
.PreQuery:
    mov     eax, dword [QueryOptions]             ; get our options
    and     eax, 0111b                      ; clear out all but lower 3 bits
    jnz     .DoQuery                        ; if !0 then we have something to search for

    push    szErrNoSearchInfo          ; 
    call    PrintString
    jmp     Done                           ;  

.DoQuery:    
    push    szQueryInfo
    call    PrintString
    
    call    QueryStopFourmSpam    

    test    dword [QueryOptions], OPT_SUBMIT
    jz      Done
    
    push    szSubmitInfo
    call    PrintString
    jmp     .CheckForKey                           

;  #########################################
;  Name       : PrintString
;  Arguments  : esp + 4 = pointer to string to print
;  Description: Prints string to terminal
;  Returns    : Nothing
;    
PrintString:
    push    dword [esp + 4]
    push    fmtstr
    call    printf
    add     esp, 4 * 2
    ret     4 * 1

;  #########################################
;  Name       : Encode
;  Arguments  : esp + 8 = pointer to string to encode
;               esp + 4 = pointer to buffer to hold encoded string
;  Description: Encodes unsafe characters
;  Returns    : Nothing
;
Encode:     
	mov     esi, [esp + 8]
    mov     edi, [esp + 4]
	dec     edi
.nc:
    movzx   eax, byte  [esi]
    
    test    al, al  ; al==0
    jz      .done
    
    inc     edi
    inc     esi
    
    cmp     al, 41h ; al=='A'
    mov     cl, al
    jb      .lA
    
    cmp     al, 5Bh ; al=='Z'
    jbe     .cpy
        
    ;al >= A
    cmp     al, 5Fh ; al=='_'
    je      .cpy
    
    ;al > _
    cmp     al, 61h ; al=='a'
    jb      .hex
    
    ; al >= a
    cmp     al, 7Ah ; al=='z'
    jbe     .cpy

.hex:
    ror     ax, 4
    mov     byte  [edi], '%'
    shr     ah, 4
    add     edi, 2
    add     al, 30h
    cmp     al, 3Ah
    jb      .F1
    add     al, 41h-3Ah
.F1:
    add     ah, 30h
    cmp     ah, 3Ah
    jb      .F2
    add     ah, 41h-3Ah
.F2:
    mov     word  [edi-1], ax
    jmp     .nc
    
.cpy:
    mov     [edi], al
    jmp     .nc
    
.space:
    mov     byte  [edi], '+'
    jmp     .nc
    
.lA:
    cmp     al, 20h
    je      .space
    
    sub     cl, 2Dh ; al=='-'
    jz      .cpy
    dec     cl      ; al=='.'
    jz      .cpy
    
    cmp     al, 30h ; al=='0'
    jb      .hex
    
    ;al >= '0'
    cmp     al, 39h ; al=='9'
    jbe     .cpy
    
    jmp     .hex
.done:
	add		edi, 2
    mov     byte  [edi],0
    
    ret     4 * 2

;~ #########################################
;~ QueryStopForumSpam 
;~ in      nothing
;~ out     nothing
;~ #########################################
QueryStopFourmSpam:   
    push    ebp
    mov     ebp, esp
    push    esi
    push    edi
    push    ebx
    sub     esp, 4                

    push    addrinfo.size            ; 
    push    0                        ; 
    push    hints
    call    memset                          ; clear out _hints struct
    add     esp, 4 * 3
    
    mov     dword [hints + addrinfo.ai_family], AF_INET       ; IPv4
    mov     dword [hints + addrinfo.ai_socktype], SOCK_STREAM ; TCP

 
    push    servinfo
    push    hints
    push    port                       ; 
    push    szSFSURL                   ; 
    call    getaddrinfo                     ; fill in servinfo struct
    add     esp, 4 * 4 
    test    eax, eax
    jz      .Good                           ; if rax == 0, no errors

    push    eax                        ; 
    call    gai_strerror                    ; convert err number to string
    add     esp, 4 * 1
    
    push    eax                             ; display err message
    call    PrintString
    jmp     .ResolutionDone

.Good:                               
    mov     edi, [servinfo]
    push    dword [edi + addrinfo.ai_protocol]
    push    dword [edi + addrinfo.ai_socktype] 
    push    dword [edi + addrinfo.ai_family] 
    call    socket
    add     esp, 4 * 3
    test    eax, eax
    jns     .DoConnect

    call    PrintError
    jmp     .SocketDone

.DoConnect:

    mov     [ebp - 4], eax
    push    dword [edi + addrinfo.ai_addrlen]
    push    dword [edi + addrinfo.ai_addr]
    push    eax
    call    connect
    add     esp, 4 * 3
    test    eax, eax
    jz      .Connected
    
    call    PrintError
    jmp     .SocketDone

.Connected:
    mov     ebx, GET_HEADER_LEN + SFS_QUERY_FIELDS_LEN 
.IPLen:
    mov     eax, [pszSpammerInfo.IP]
    test    eax, eax
    jz      .NameLen
    push    eax
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax

.NameLen:
    mov     eax, [pszSpammerInfo.Name]
    test    eax, eax
    jz      .EmailLen   
    push    eax
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax

.EmailLen:
    mov     eax, [pszSpammerInfo.Email]
    test    eax, eax
    jz      .Alloc
    push    eax
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax
    
.Alloc:
    add     ebx, 1
    push    ebx
    call    malloc
    add     esp, 4 * 1
    mov     edi, eax

.CreateQueryHeader:
    push    szHeadGet                  ; "GET ", 0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szSFSQueryAPI              ; '/api?', 0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.IP_Param1:
    cmp     dword [pszSpammerInfo.IP], 0
    je      .Name_Param1

    push    szSFSQueryIP               ; ip=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    dword [pszSpammerInfo.IP]
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.CheckForNameParam:
    cmp     dword [pszSpammerInfo.Name], 0
    je      .CheckForEmailParam

.NameParam:
    push    szAmp                      ; &
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    szSFSQueryName             ; name=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Name]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
                
.CheckForEmailParam:
    cmp     dword [pszSpammerInfo.Email], 0
    je     .LastParam

.EmailParam:
    push    szAmp                      ; &
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    szSFSQueryEmail            ; email=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Email]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    jmp     .LastParam

.Name_Param1:
    cmp     dword [pszSpammerInfo.Name], 0
    je      .Email_Param1

    push    szSFSQueryName        
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    dword [pszSpammerInfo.Name]
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    jmp     .CheckForEmailParam

.Email_Param1:
    push    szSFSQueryEmail            ; email=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Email]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
      
.LastParam:
    push    szSFSQueryFmt              ; &f=json
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    ;~ ; add on any options
    cmp     dword [pszSpammerInfo.Email], 0
    je     .CheckName

    mov     ecx, [QueryOptions]
    and     ecx, OPT_NO_EMAIL
    jz      .CheckName

    push    szSFSNoEmail              
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
.CheckName:   
    cmp     dword [pszSpammerInfo.Name], 0
    je      .CheckIp

    mov     ecx, [QueryOptions]
    and     ecx, OPT_NO_NAME
    jz      .CheckIp

    push    szSFSNoName               
    push    eax
    call    stpcpy    
    add     esp, 4 * 2
    
.CheckIp:
    cmp     dword [pszSpammerInfo.IP], 0
    je      .CheckAll

    mov     ecx, [QueryOptions]
    and     ecx, OPT_NO_IP
    jz      .CheckAll

    push    szSFSNoIP              
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.CheckAll:
    mov     ecx, [QueryOptions]
    and     ecx, OPT_NO_ALL
    jz      .CheckTor

    push    szSFSNoAll             
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.CheckTor:
    mov     ecx, [QueryOptions]
    and     ecx, OPT_NO_TOR
    jz      .Over

    push    szSFSNoTor            
    push    eax
    call    stpcpy  
    add     esp, 4 * 2
        
.Over:  
    push    szHeadVersion0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szHeadHost
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szSFSURL
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szHeadAgent
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szVersion
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    szHeadClose
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
                    
    push    edi
    call    strlen
    add     esp, 4 * 1
    
    push    0
    push    eax
    push    edi
    push    dword [ebp - 4]
    call    send
    add     esp, 4 * 4
    
    push    edi
    call    free 
    add     esp, 4 * 1
    
    push    MAX_RECV_BUFFER_SIZE
    call    malloc
    add     esp, 4 * 1
    mov     edi, eax

%define RecvBufOffset       esi
%define RecvBufSpaceLeft    ebx

    mov     RecvBufSpaceLeft, MAX_RECV_BUFFER_SIZE - 1
    mov     RecvBufOffset, 0
.Recv:        
    mov     ecx, edi
    add     ecx, RecvBufOffset
    
    push    0
    push    RecvBufSpaceLeft
    push    ecx
    push    dword [ebp -4]
    call    recv
    add     esp, 4 * 4
    add     RecvBufOffset, eax
    sub     RecvBufSpaceLeft, eax
    test    eax, eax
    jnz     .Recv    

    mov     byte [edi + RecvBufOffset], 0   ; NULL terminate incomming data
    
    push    edi
    call    GetHTTPResponseCode    
    cmp     eax, "200 "
    jne     .RecvDone

.GoodResponse:
    push    edi
    call    GetQueryReply    
    mov     esi, eax
    
.GetRetVal:
    mov     al, byte [esi]
    cmp     al, ":"
    je      .CheckRetVal
    add     esi, 1
    jmp     .GetRetVal
    
.CheckRetVal:
    mov     al, byte [esi + 1]
    cmp     al, "1"
    jne      .QueryError
    
    push    szHeadSeen
    push    szHeadConf
    push    szHeadFreq
    push    szArgs
    push    fmtrow
    call    printf
    add     esp, 4 * 5
    
.GetIPInfo:    
    cmp     dword [pszSpammerInfo.IP], 0
    je      .GetNameInfo

.ParseIP:       
    push    szIP
    push    esi
    call    ParseSFSQuery

.DisplayIPInfo:
    push    szRowIP
    call    PrintRow
 
.GetNameInfo:   
    cmp     dword [pszSpammerInfo.Name], 0
    je      .GetEmailInfo
    
.ParseName: 
    push    szUserName
    push    esi
    call    ParseSFSQuery

.DisplayNameInfo:
    push    szRowName
    call    PrintRow
    
.GetEmailInfo:
    cmp     dword [pszSpammerInfo.Email], 0
    je      .RecvDone

.ParseEmail:    
    push    szEmail
    push    esi
    call    ParseSFSQuery

.DisplayEmailInfo:
    push    szRowEmail
    call    PrintRow
    
.QueryError:
.RecvDone:    
    push    edi
    call    free
    add     esp, 4 * 1

.SocketDone:
    push   dword [ebp - 4]
    call    close
    add     esp, 4 * 1
    
    push    dword [servinfo]
    call    freeaddrinfo
    add     esp, 4 * 1
    
.ResolutionDone:   
    add     esp,  4
    pop     ebx
    pop     edi
    pop     esi
    mov     esp, ebp
    pop     ebp
    ret

PrintError:   
    push    dword [errno]
    call    strerror
    add     esp, 4 * 1
    push    eax
    call    PrintString
    ret

PrintRow:    
    mov     eax, pSFS_Reply
    push    dword [eax + 4 * 2]
    push    dword [eax + 4 * 1]
    push    dword [eax + 4 * 0]
    push    dword [esp + 16]
    push    fmtrow
    call    printf
    add     esp, 4 * 5
    ret     4 * 1

;~ #########################################
;~ GetQueryReply = Parse HTTP reply for payload
;~ in      rsp + 4 = address of reply
;~ out     eax = pointer to payload
;~ #########################################
GetQueryReply:
    
    mov     ecx, [esp + 4]
    sub     ecx, 1
.next:     
    add     ecx, 1
    mov     al, byte [ecx]
    cmp     al, "{"
    jne     .next
    
    mov     eax, ecx
    ret     4 * 1

;~ #########################################
;~ GetHTTPResponseCode = find HTTP Response code
;~ in      esp + 4 = address of string to search
;~ out     eax = pointer to first char of response code
;~ #########################################
GetHTTPResponseCode:
    mov     ecx, [esp + 4]
    sub     ecx, 1
.SkipHTTP:
    add     ecx, 1
    mov     al, byte [ecx]
    cmp     al, " "
    jne     .SkipHTTP
    add     ecx, 1
    mov     eax, dword [ecx]
    ret     4 * 1

;~ #########################################
;~ esp + 8 = needle to search for
;~ esp + 4 = haystack to search
ParseSFSQuery:
    push    ebp
    mov     ebp, esp
    push    esi
    push    edi

;ip":{"lastseen":"2014-11-07 03:50:52","frequency":5,"appears":1,"confidence":4.98}}

    push    dword [ebp + 12]
    push    dword [ebp + 8]
    call    strstr                          ; Find needle
    add     esp, 4 * 2
    mov     esi, eax                        ; save pointer to first char

    push    szAppears
    push    eax
    call    strstr                          ; find `appears`
    add     esp, 4 * 2
    
    mov     cl, byte[eax + 9]              ; skip over it
    cmp     cl, "0"                        ; If value != ASCII 0, not a spammer
    jne     .HaveSpammerInfo

.NoInfo:
    mov     ecx, SFSReplyStruc         
    mov     dword [ecx], 0                      ; fill in structure with ASCII 0
    mov     dword [ecx + 32], 0
    mov     dword [ecx + 48], 0
    jmp     .Done                           ; and be done with this

.HaveSpammerInfo:
    push    szLastSeen
    push    esi
    call    strstr                          ; find `lastseen`
    add     esp, 4 * 2
    add     eax, 11                         ; skip over it
    lea     edi, [SFSReplyStruc.Seen]
    
.GetSeen:
    mov     cl, byte [eax]
    cmp     cl, '"'
    je      .SeenDone
    mov     byte [edi], cl
    inc     edi
    inc     eax
    jmp     .GetSeen

.SeenDone:
    mov     byte [edi], 0
    
    push    szFrequency
    push    esi
    call    strstr
    add     esp, 4 * 2
    add     eax, 11
    lea     edi, [SFSReplyStruc.Freq]
    
.GetFreq:
    mov     cl, byte [eax]
    cmp     cl, ','
    je      .FreqDone
    mov     byte [edi], cl
    inc     edi
    inc     eax
    jmp     .GetFreq

.FreqDone:
    mov     byte [edi], 0
    
    push    szConf
    push    esi
    call    strstr
    add     esp, 4 * 2
    add     eax, 12
    lea     edi, [SFSReplyStruc.Conf]
    
.GetConf:
    mov     cl, byte [eax]
    cmp     cl, '}'
    je      .ConfDone
    mov     byte [edi], cl
    inc     edi
    inc     eax
    jmp     .GetConf

.ConfDone:
     mov     byte [edi], 0
    
.Done:
    pop     edi
    pop     esi
    mov     esp, ebp
    pop     ebp
    ret     4 * 2

SubmitStopFourmSpam:
  push    ebp
    mov     ebp, esp
    push    esi
    push    edi
    push    ebx
    sub     esp, 4                

    push    addrinfo.size            ; 
    push    0                        ; 
    push    hints
    call    memset                          ; clear out _hints struct
    add     esp, 4 * 3
    
    mov     dword [hints + addrinfo.ai_family], AF_INET       ; IPv4
    mov     dword [hints + addrinfo.ai_socktype], SOCK_STREAM ; TCP

 
    push    servinfo
    push    hints
    push    port                       ; 
    push    szSFSURL                   ; 
    call    getaddrinfo                     ; fill in servinfo struct
    add     esp, 4 * 4 
    test    eax, eax
    jz      .Good                           ; if rax == 0, no errors

    push    eax                        ; 
    call    gai_strerror                    ; convert err number to string
    add     esp, 4 * 1
    
    push    eax                             ; display err message
    call    PrintString
    jmp     .ResolutionDone

.Good:                               
    mov     edi, [servinfo]
    push    dword [edi + addrinfo.ai_protocol]
    push    dword [edi + addrinfo.ai_socktype] 
    push    dword [edi + addrinfo.ai_family] 
    call    socket
    add     esp, 4 * 3
    test    eax, eax
    jns     .DoConnect

    call    PrintError
    jmp     .SocketDone

.DoConnect:

    mov     [ebp - 4], eax
    push    dword [edi + addrinfo.ai_addrlen]
    push    dword [edi + addrinfo.ai_addr]
    push    eax
    call    connect
    add     esp, 4 * 3
    test    eax, eax
    jz      .Connected
    
    call    PrintError
    jmp     .SocketDone

.Connected:
    mov     ebx, GET_HEADER_LEN + SFS_SUBMIT_FIELDS_LEN
.IPLen:
    push    dword [pszSpammerInfo.IP]
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax

.NameLen:
    push    dword [pszSpammerInfo.Name]
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax

.EmailLen:
    push    dword [pszSpammerInfo.Email]
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax

.EvidenceLen:
    test    dword [QueryOptions], OPT_EVIDENCE
    jz      .KeyLen
    
    push    dword [pszSpammerInfo.Evidence]
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax
    
.KeyLen:
    push    dword [pszSpammerInfo.APIKey]
    call    strlen
    add     esp, 4 * 1
    add     ebx, eax
    
.Alloc:
    add     ebx, 1
    push    ebx
    call    malloc
    add     esp, 4 * 1    
    mov     edi, eax

.CreateQueryHeader:
    push    szHeadGet                  ; "GET ", 0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    szSFSSubmitAPI              ; '/add.php', 0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.NameParam:   
    push    szSFSSubmitName             ; name=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Name]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
.IP_Param:
    push    szSFSSubmitIP               ; ip=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    dword [pszSpammerInfo.IP]
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.EmailParam:   
    push    szSFSSubmitEmail            ; email=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Email]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
.EvidenceParam:
    test    dword [QueryOptions], OPT_EVIDENCE
    jz      .APIKeyParam

    push    szSFSSubmitEvidence            ; email=
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    dword [pszSpammerInfo.Evidence]          
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
.APIKeyParam:
    push    szSFSSubmitKey
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    dword [pszSpammerInfo.APIKey]
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
.Over:  
    push    szHeadVersion0
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szHeadHost
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szSFSURL
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szHeadAgent
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szVersion
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
        
    push    szHeadClose
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    szNewLine
    push    eax
    call    stpcpy
    add     esp, 4 * 2
    
    push    edi
    call    strlen
    add     esp, 4 * 1
    
    push    0
    push    eax
    push    edi
    push    dword [ebp - 4]
    call    send
    add     esp, 4 * 4
    
    push    edi
    call    free 
    add     esp, 4 * 1

    push    MAX_RECV_BUFFER_SIZE
    call    malloc
    add     esp, 4 * 1
    mov     edi, eax

%define RecvBufOffset       esi
%define RecvBufSpaceLeft    ebx

    mov     RecvBufSpaceLeft, MAX_RECV_BUFFER_SIZE - 1
    mov     RecvBufOffset, 0
.Recv:        
    mov     ecx, edi
    add     ecx, RecvBufOffset
    
    push    0
    push    RecvBufSpaceLeft
    push    ecx
    push    dword [ebp -4]
    call    recv
    add     esp, 4 * 4
    add     RecvBufOffset, eax
    sub     RecvBufSpaceLeft, eax
    test    eax, eax
    jnz     .Recv    

    mov     byte [edi + RecvBufOffset], 0   ; NULL terminate incomming data
    
    push    edi
    call    GetHTTPResponseCode    
    cmp     eax, "200 "
    jne     .BadResponse

    push    szAnotherNail
    call    PrintString
    jmp     .RecvDone
    
.BadResponse:
    push    edi
    call    GetSubmitReply    
    
    push    eax
    call    PrintString    

.RecvDone:    
    push    edi
    call    free
    add     esp, 4 * 1

.SocketDone:
    push    dword [ebp - 4]
    call    close
    add     esp, 4 * 1
    
    push    dword [servinfo]
    call    freeaddrinfo
    add     esp, 4 * 1
    
.ResolutionDone:   
    add     esp,  4
    pop     ebx
    pop     edi
    pop     esi
    mov     esp, ebp
    pop     ebp
    ret
    
;~ #########################################
;~ GetSubmitReply = Parse HTTP reply for payload
;~ in      esp + 4 = address of reply
;~ out     eax = pointer to null terminated payload
;~ #########################################
GetSubmitReply:
    mov     ecx, [esp + 4]
    sub     ecx, 1
.next:
    add     ecx, 1
    mov     al, byte [ecx]
    cmp     al, "<"
    jne     .next
    add     ecx, 3
    mov     edx, ecx

    sub     ecx, 1
.FindClose:
    add     ecx, 1
    mov     al, byte [ecx]
    cmp     al, "<"
    jne     .FindClose
    mov     byte [ecx], 0
    
    mov     eax, edx
    ret     4 * 1
