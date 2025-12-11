Advanced topics is cyber system security project

Hello and welcome to your course project.

Please download and unzip your project from Moodle.

First run the setup script

student@6858-v22:\~/lab$ **sudo ./setup.sh**  
Remember it is your responsibility \! to make the script run correctly and install all the desired packages\!

make sure you can compile the zookws web server:

student@6858-v22:\~/lab$ **make**

cc zookd.c \-c \-o zookd.o \-m64 \-g \-std=c99 \-Wall \-D\_GNU\_SOURCE \-static \-fno-stack-protector

cc http.c \-c \-o http.o \-m64 \-g \-std=c99 \-Wall \-D\_GNU\_SOURCE \-static \-fno-stack-protector

cc \-m64  zookd.o http.o  \-lcrypto \-o zookd

cc \-m64 zookd.o http.o  \-lcrypto \-o zookd-exstack \-z execstack  
The component of zoo-web-server that receives HTTP requests is zookd. It is written in C and serves static files and executes dynamic scripts. For now you don't have to understand the dynamic scripts yet; they are written in Python and the exploits in this lab apply only to C code. The HTTP-related code is in http.c. [Here](http://www.garshol.priv.no/download/text/http-tut.html) is a tutorial about the HTTP protocol and CGI.

**Task 0 : Run the server and create users transfer money between users- show the professor that everything works well.**

Tip: the setup script should have already installed all  packages .You should make sure you have python installed on your computer as well as the libraries the webserver Flask and the SQLAlchemy toolkit. If you don’t On your terminal run :

student@6858-v22:\~/lab$ pip install \-U Flask SQLAlchemy

**Section 1 : attack**

Part 1: Finding buffer overflows

In the first part of this lab assignment, you will find buffer overflows in the provided web server. To do this lab, you will need to understand the basics of buffer overflows. To help you get started with this, you should read [Smashing the Stack in the 21st Century](https://thesquareplanet.com/blog/smashing-the-stack-21st-century/), which goes through the details of how buffer overflows work, and how they can be exploited.

**Exercise 1\.** Study the web server's C code (in zookd.c and http.c), and find one example of code that allows an attacker to overwrite the return address of a function.

First you need to map the application. Which processes and threads run ? 

**Draw** the application architecture . follow the C and python logic . find how static and dynamic pages are loaded and how the CGI is loaded \-  you will be required to submit your answers.

look for buffers allocated on the stack. Write down a description of the vulnerability. For your vulnerability, describe the buffer which may overflow, how you would structure the input to the web server (i.e., the HTTP request) to overflow the buffer and overwrite the return address, and the call stack that will trigger the buffer overflow (i.e., the chain of function calls starting from process\_client).

It is worth taking your time on this exercise and familiarizing yourself with the code, because your next job is to exploit the vulnerability you identified. **Draw** a stack diagram like the figures in [Smashing the Stack in the 21st Century](https://thesquareplanet.com/blog/smashing-the-stack-21st-century/).

Now, you will start developing exploits to take advantage of the buffer overflows you have found above. We have provided template Python code for an exploit in /home/student/lab/exploit-template.py, which issues an HTTP request. The exploit template takes two arguments, the server name and port number, so you might run it as follows to issue a request to zookws running on localhost:

student@6858-v22:\~/lab$ **./zookd 8080 &**

\[1\] 2676

student@6858-v22:\~/lab$ **./exploit-template.py localhost 8080**

HTTP request:

b'GET / HTTP/1.0

You are free to use this template, or write your own exploit code from scratch. You may find gdb useful in building your exploits (though it is not required for you to do so). As zookd forks off many processes (one for each client), it can be difficult to debug the correct one. The easiest way to do this is to run the web server ahead of time with clean-env.sh and then attach gdb to an already-running process with the \-p flag. You can find the PID of a process by using pgrep; for example, to attach to zookd-exstack, start the server and, in another shell, run

student@6858-v22:\~/lab$ **gdb \-p $(pgrep zookd-)**

...

(gdb) **break *your-breakpoint***

Breakpoint 1 at 0x1234567: file zookd.c, line 999\.

(gdb) **continue**

Continuing.

Keep in mind that a process being debugged by gdb will not get killed even if you terminate the parent zookd process using ^C. If you are having trouble restarting the web server, check for leftover processes from the previous run, or be sure to exit gdb before restarting zookd. You can also save yourself some typing by using b instead of break, and c instead of continue.

When a process being debugged by gdb forks, by default gdb continues to debug the parent process and does not attach to the child. Since zookd forks a child process to service each request, you may find it helpful to have gdb attach to the child on fork, using the command set follow-fork-mode child. 

Or alternatively, run the process using gdb and setup the debugger to follow the child process:

student@6858-v22:\~/lab$ gdb zookd

...

(gdb) set follow-fork-mode child

(gdb) break your-breakpoint

Breakpoint 1 at 0x1234567: file zookd.c, line 999\.

(gdb) r 8080

As you develop your exploit, you may discover that it causes the server to hang as opposed to crash, depending on what buffer overflow you are trying to take advantage of and what data you are overwriting in the running server. You can dig into the details of why the hang happens, to understand how you are affecting the server's execution, in order to make your exploit avoid the hang and instead crash the server. Or you can choose to exploit a different buffer overflow that avoids the hanging behavior.

**Exercise 2\.** Write an exploit that uses a buffer overflow to crash the web server (or one of the processes it creates). You do not need to inject code at this point. Verify that your exploit crashes the server by checking the last few lines of dmesg | tail, using gdb, or observing that the web server crashes (i.e., it will print Child process 9999 terminated incorrectly, receiving signal 11)

Provide the code for the exploit in a file called exploit-2.py.

The vulnerability you found in Exercise 1 may be too hard to exploit.

 Feel free to find and exploit a different vulnerability.

Part 2: Code injection

In this part, you will use your buffer overflow exploits to inject code into the web server. The goal of the injected code will be to unlink (remove) a sensitive file on the server, namely /home/student/password.txt. Use zookd-exstack, since it has an executable stack that makes it easier to inject code. The zookws web server should be started as follows.

student@6858-v22:\~/lab$ **./zookd 8080**

You can build the exploit in two steps. First, write the shell code that unlinks the sensitive file, namely /home/student/password.txt. Second, embed the compiled shell code in an HTTP request that triggers the buffer overflow in the web server.

When writing shell code, it is often easier to use assembly language rather than higher-level languages, such as C. This is because the exploit usually needs fine control over the stack layout, register values and code size. The C compiler will generate additional function preludes and perform various optimizations, which makes the compiled binary code unpredictable.

We have provided shell code for you to use in /home/student/lab/shellcode.S, along with Makefile rules that produce /home/student/lab/shellcode.bin, a compiled version of the shell code, when you run **make**. The provided shell code is intended to exploit setuid-root binaries, and thus it runs a shell. You will need to modify this shell code to instead unlink /home/\<student\>/lab/password.txt.

To help you develop your shell code for this exercise, we have provided a program called run-shellcode that will run your binary shell code, as if you correctly jumped to its starting point. For example, running it on the provided shell code will cause the program to execve("/bin/sh"), thereby giving you another shell prompt:

student@6858-v22:\~/lab$ **./run-shellcode shellcode.bin**  
**Exercise 3 (warm-up).** Modify shellcode.S to unlink /home/student/password.txt. Your assembly code can invoke the SYS\_unlink system call

To test whether the shell code does its job, run the following commands:

student@6858-v22:\~/lab$ **make**

student@6858-v22:\~/lab$ **touch \~/password.txt**

student@6858-v22:\~/lab$ **./run-shellcode shellcode.bin**

\# Make sure /home/student/password.txt is gone

student@6858-v22:\~/lab$ **ls \~/password.txt**

ls: cannot access /home/student/password.txt: No such file or directory  
You may find [strace](https://linux.die.net/man/1/strace) useful when trying to figure out what system calls your shellcode is making. Much like with gdb, you attach strace to a running program:

student@6858-v22:\~/lab$ **strace \-f \-p $(pgrep zookd-)**  
It will then print all of the system calls that program makes. If your shell code isn't working, try looking for the system call you think your shell code should be executing (i.e., unlink), and see whether it has the right arguments.

Next, we construct a malicious HTTP request that injects the compiled byte code to the web server, and hijack the server's control flow to run the injected code. When developing an exploit, you will have to think about what values are on the stack, so that you can modify them accordingly.

When you're constructing an exploit, you will often need to know the addresses of specific stack locations, or specific functions, in a particular program. One way to do this is to add printf() statements to the function in question. For example, you can use printf("Pointer: %p ", \&x); to print the address of variable x or function x. However, this approach requires some care: you need to make sure that your added statements are not themselves changing the stack layout or code layout. 

A more fool-proof approach to determine addresses is to use gdb. For example, suppose you want to know the stack address of the pn\[\] array in the http\_serve function in zookd-exstack, and the address of its saved return pointer. You can obtain them using gdb by first starting the web server and then attaching gdb to it:

student@6858-v22:\~/lab$ **gdb \-p $(pgrep zookd-)**

...

(gdb) **break http\_serve**

Breakpoint 1 at 0x5555555561c4: file http.c, line 275\.

(gdb) **continue**

Continuing.  
Be sure to run gdb from the \~/lab directory, so that it picks up the set follow-fork-mode child command from \~/lab/.gdbinit. Now you can issue an HTTP request to the web server, so that it triggers the breakpoint, and so that you can examine the stack of http\_serve.

student@6858-v22:\~/lab$ **curl localhost:8080**  
This will cause gdb to hit the breakpoint you set and halt execution, and give you an opportunity to ask gdb for addresses you are interested in. Also you can examine a certain address or variable with the [x command](https://visualgdb.com/gdbreference/commands/x):

Thread 2.1 "zookd-exstack" hit Breakpoint 1, http\_serve (fd=4, name=0x55555575fcec "/") at http.c:275

275         void (\*handler)(int, const char \*) \= http\_serve\_none;

(gdb) **print \&pn**

$1 \= (char (\*)\[2048\]) 0x7fffffffd4a0

(gdb) **info frame**

Stack level 0, frame at 0x7fffffffdcd0:

 rip \= 0x5555555561c4 in http\_serve (http.c:275); saved rip \= 0x55555555587b

 called by frame at 0x7fffffffed00

 source language c.

 Arglist at 0x7fffffffdcc0, args: fd=4, name=0x55555575fcec "/"

 Locals at 0x7fffffffdcc0, Previous frame's sp is 0x7fffffffdcd0

 Saved registers:

  rbx at 0x7fffffffdcb8, rbp at 0x7fffffffdcc0, rip at 0x7fffffffdcc8

(gdb) x/16x \&pn

From this, you can tell that, at least for this invocation of http\_serve, the pn\[\] buffer on the stack lives at address 0x7fffffffd4a0, and the saved value of %rip (the return address in other words) is at 0x7fffffffdcc8. If you want to see register contents, you can also use **info registers**.  Also if you run the server thru the gdb then the absolute address will remain static.

Now it's your turn to develop an exploit.

**Exercise 4\.** Starting from one of your exploits from Exercise 2, construct an exploit that hijacks the control flow of the web server and unlinks /home/student/password.txt. Save this exploit in a file called exploit-2.py.

Verify that your exploit works; you will need to recreate /home/student/password.txt after each successful exploit run.

Suggestion: first focus on obtaining control of the program counter. Sketch out the stack layout that you expect the program to have at the point when you overflow the buffer, and use gdb to verify that your overflow data ends up where you expect it to. Step through the execution of the function to the return instruction to make sure you can control what address the program returns to. The next, stepi, and x commands in gdb should prove helpful.

Once you can reliably hijack the control flow of the program, find a suitable address that will contain the code you want to execute, and focus on placing the correct code at that address---e.g. a derivative of the provided shell code.

In the exploit-template.py there are instruction on how to use little endian and global with the names of where the pointer is and where the return address is \-use them\!

The standard C compiler used on Linux, gcc, implements a version of stack canaries (called SSP). You can explore whether GCC's version of stack canaries would or would not prevent a given vulnerability by using the SSP-enabled versions of zookd: zookd-withssp.

**Section 2 : architectural considerations**

Part 1: Secure your server

**Exercise 1\.** In your browser, connect to the zoobar Web site, and create two user accounts. Login in as one of the users, and transfer zoobars from one user to another by clicking on the transfer link and filling out the form. Play around with the other features too to get a feel for what it allows users to do. In short, a registered user can update his/her profile, transfer "zoobars" (credits) to another user, and look up the zoobar balance, profile, and transactions of other users in the system.

Read through the code of zoobar and see how transfer.py gets invoked when a user sends a transfer on the transfer page. A good place to start for this part of the lab is templates/transfer.html, \_\_init\_\_.py, transfer.py, and bank.py in the zoobar directory.

This lab will introduce you to privilege separation and serverside sandboxing, in the context of a simple python web application called zoobar, where users transfer "zoobars" (credits) between each other. The main goal of privilege separation is to ensure that if an adversary compromises one part of an application, the adversary doesn't compromise the other parts too. To help you privilege-separate this application, we will use the OKWS web server model, discussed in lecture. In this section, you will set up a privilege-separated web server, examine possible vulnerabilities, and break up the application code into less-privileged components to minimize the effects of any single vulnerability.Change your application to include the following components:

![DiagramDescription automatically generated][image1]

We will only implement zookld, zookd and the services of the full architecture.

**zookld** (runs as root) \- the launcher daemon responsible for launching and keep alive of all other components (using the child signal).

The steps for launching a single service are: 

1\. zookld opens 2 socket pairs; one for HTTP connection forwarding (tcp socket), and one for RPC control messages (unix socket). 

2\. okld calls fork. 

3\. In the child address space, okld picks a fresh UID/GID pair (x.x), sets the new process’s group list to {x} and its UID to x. It then changes directories into jail and chroots this service. 

4\. Still in the child address space, okld calls execve, launching the Web service. The new Web service process inherits three file descriptors: one for receiving forwarded HTTP connections, one for receiving RPC control messages (a descriptor or the socket name as explained below. 

Write a code in file zookld.c which forks chroots and sets uids and group ids to each process.

Use Unix sockets to build the RPCs since a Unix-socket can pass file descriptors between processes.  code is available at http.c specifically the calls sendfd() and recvfd()and [here](https://stackoverflow.com/questions/28003921/sending-file-descriptor-by-linux-socket) is a code example for the general flow.

zookld also keeps alive the processes in case they fall. Zookld catches SIGCHLD when services die. Upon receiving a non-zero exit status, zookld prompts the processes again and changes the owner and mode of any core files left behind, rendering them inaccessible to other processes. 

**zookd** – the http request dispatcher.

The zookd process accepts incoming HTTP requests and demultiplexes them based on the “Request-URI” in their first lines. For example, the HTTP/1.1 standard defines the first line of a GET request as: 

GET /⟨abs path⟩?⟨query⟩ HTTP/1.1 

Upon receiving such a request, zookd looks up a Web service corresponding to abs path in its dispatch table. If successful, zookd forwards the remote client’s file descriptor to the requested service. If the lookup is successful but the service is marked “broken,” zookd sends an HTTP 500 error to the remote client. If the request did not match a known service, zookd returns an HTTP 404 error 

Upon startup, zookd inherits one file descriptor from okld for RPC control messages.

 zookd receives one such pair for each service launched. The HTTP connection is the sink to which zookd sends incoming HTTP requests from external clients after successful demultiplexing 

**Zooksvc –** loads static and (for now) dynamic pages.

Note that you need to pass for each request the environment variables (it changes each request and the dispatcher and service may not be synchronized).

The service does not have to fork any more but receive the variable call env\_deserialize() and at the end call clearenv(); 

**(warm up exercise)** First of all start by getting familiar with the linux inter-process communication (IPC), for example using [socketpair](https://man7.org/linux/man-pages/man2/socketpair.2.html).   
Start by creating two simple c programs, the first should send messages to the second process, while the second process should receive the messages. Once you’re familiar with the concept, proceed to the next exercise.  
If you decide to implement IPC using sockets then you might make use of the functions sendfd and recvfd provided in the http.c file as described above.

Exercise 2.1. Implement privilege separation as described above, where you create a loader process which keeps-alive a dispatcher and a general service processes with proper jail directory and UID/GID.  
Run the attack from section 1\. Does it work?  
You’ll need to show that it doesn’t work any more\!       
This can be achieved by running zookld not as root user (which discounts all your privilege separation)  
Reminder: remember to run your loader as a sudoer/root, since [chroot](https://man7.org/linux/man-pages/man2/chroot.2.html) / [setuid](https://man7.org/linux/man-pages/man2/setuid.2.html) / [setgid](https://man7.org/linux/man-pages/man2/setgid.2.html) syscalls require root privileges.   
Note: when changing the root directory of a process, it will lose access to all files outside the jail, this includes libraries used during runtime\!.  
The setup script should have taken care of it but if not  
Make sure to link necessary libraries to the jail directory, such as:  
$ mount \--bind /usr  /jail/usr  
$ mount \--bind /lib  /jail/lib  
$ mount \--bind /lib54  /jail/lib64  
Also you need to copy all executables and the zoobar folder to /jail, Alternatively you can make the jail library your /lab folder. 

## 

## **Part 3: Privilege-separating the login service in Zoobar**

Right now, an adversary that exploits a vulnerability in any part of the Zoobar application can obtain all user passwords from the person database.  
The first step towards protecting passwords will be to create a service that deals with user passwords and cookies, so that only that service can access them directly, and the rest of the Zoobar application cannot. In particular, we want to separate the code that deals with user authentication (i.e., passwords and tokens) from the rest of the application code. The current zoobar application stores everything about the user (their profile, their zoobar balance, and authentication info) in the Person table (see zoodb.py). We want to move the authentication info out of the Person table into a separate Cred table (Cred stands for Credentials), and move the code that accesses this authentication information (i.e., auth.py) into a separate service.  
The reason for splitting the tables is that the tables are stored in the file system in zoobar/db/, and are accessible to all Python code in Zoobar. This means that an attacker might be able to access and modify any of these tables, and we might never find out about the attack. However, once the authentication data is split out into its own database, we can set Unix file and directory permissions such that only the authentication service---and not the rest of Zoobar---can access that information.

To illustrate how our RPC library might be used, look at the implemention of the auth-service, in zoobar/auth-server.py. This service needs to be invoked by zookld; 

auth-server.py is implemented by defining an RPC class AuthRpcServer that inherits from RpcServer, which in turn comes from zoobar/rpclib.py. The AuthRpcServer  RPC class defines the methods that the server supports, and rpclib invokes those methods when a client sends a request. 

auth-server.py starts the server by calling run\_sockpath\_fork(sockpath). This function listens on a UNIX-domain socket. The socket name comes from the argument passed by zookld, which in this case is /authsvc/sock . When a client connects to this socket, the function forks the current process. One copy of the process receives messages and responds on the just-opened connection, while the other process listens for other clients that might open the socket.

We have also included a simple client of this auth service as part of the Zoobar web application. In particular, if you go to the URL /zoobar/index.cgi/login, the request should be routed tthrough zoobar/login.py. That code uses the RPC client (implemented by rpclib) to connect to the auth service at /authsvc/sock and invoke the login operation. 

The RPC client-side code in rpclib is implemented by the call method of the RpcClient class. This method formats the arguments into a string, writes the string on the connection to the server, and waits for a response (a string). On receiving the response, call parses the string, and returns the results to the caller.

Specifically, your job will be as follows:

* Decide what interface your authentication service should provide (i.e., what functions it will run for clients). Look at the code in login.py and auth.py, and decide what needs to run in the authentication service, and what can run in the client (i.e., be part of the rest of the zoobar code). Keep in mind that your goal is to protect both passwords and tokens. We have provided initial RPC stubs for the client in the file zoobar/auth\_client.py.  
* Create a new auth\_svc service for user authentication.I have provided an initial file for you, zoobar/auth-server.py. The implementation of this service should use the existing functions in auth.py. The service is loaded by the zookld with the name of the socket as the input parameter.  
* Split the user credentials (i.e., passwords and tokens) from the Person database into a separate Cred database, stored in /zoobar/db/cred. Don't keep any passwords or tokens in the old Person database.  
* Modify the login code in login.py to invoke your auth service instead of calling auth.py directly.  
* Modify zoobar/zookdb.py to include Cred table with username password token (along the lines of the other tables) \- class Cred() and cred\_setup().  
* Modify zoobar/auth.py to include the newly tables.

**Exercise 3\.** Implement privilege separation for user authentication, as described above. Don't forget to create a regular Person database entry for newly registered users.  
Now, we will further improve the security of passwords, by using hashing and salting. The current authentication code stores an exact copy of the user's password in the database. Thus, if an adversary somehow gains access to the cred.db file, all of the user passwords will be immediately compromised. Worse yet, if users have the same password on multiple sites, the adversary will be able to compromise users' accounts there too\!  
Hashing protects against this attack, by storing a hash of the user's password (i.e., the result of applying a hash function to the password), instead of the password itself. If the hash function is difficult to invert (i.e., is a cryptographically secure hash), an adversary will not be able to directly obtain the user's password. However, a server can still check if a user supplied the correct password during login: it will just hash the user's password, and check if the resulting hash value is the same as was previously stored.

One weakness with hashing is that an adversary can build up a giant table (called a "rainbow table"), containing the hashes of all possible passwords. Then, if an adversary obtains someone's hashed password, the adversary can just look it up in its giant table, and obtain the original password.

To defeat the rainbow table attack, most systems use *salting*. With salting, instead of storing a hash of the password, the server stores a hash of the password concatenated with a randomly-generated string (called a salt). To check if the password is correct, the server concatenates the user-supplied password with the salt, and checks if the result matches the stored hash. Note that, to make this work, the server must store the salt value used to originally compute the salted hash\! However, because of the salt, the adversary would now have to generate a separate rainbow table for every possible salt value. This greatly increases the amount of work the adversary has to perform in order to guess user passwords based on the hashes.

A final consideration is the choice of hash function. Most hash functions, such as MD5 and SHA1, are designed to be fast. This means that an adversary can try lots of passwords in a short period of time, which is not what we want\! Instead, you should use a special hash-like function that is explicitly designed to be *slow*. A good example of such a hash function is [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2), which stands for Password-Based Key Derivation Function (version 2).

**Exercise 4\.** Implement password hashing and salting in your authentication service. In particular, you will need to extend your Cred table to include a salt column; modify the registration code to choose a random salt, and to store a hash of the password together with the salt, instead of the password itself; and modify the login code to hash the supplied password together with the stored salt, and compare it with the stored hash. Don't remove the password column from the Cred table (the check for exercise 5 requires that it be present); you can store the hashed password in the existing password column.

To implement PBKDF2 hashing, you can use the [Python PBKDF2 module](http://www.dlitz.net/software/python-pbkdf2/). Roughly, you should import pbkdf2, and then hash a password using pbkdf2.PBKDF2(password, salt).hexread(32). We have provided a copy of pbkdf2.py in the zoobar directory. Do not use the random.random function to generate a salt as [the documentation of the random module](http://docs.python.org/2/library/random.html) states that it is not cryptographically secure. A secure alternative is the function os.urandom.

A surprising side-effect of using a very computationally expensive hash function like PBKDF2 is that an adversary can now use this to launch denial-of-service (DoS) attacks on the server's CPU. For example, the popular Django web framework recently posted a [security advisory](https://www.djangoproject.com/weblog/2013/sep/15/security/) about this, pointing out that if an adversary tries to log in to some account by supplying a very large password (1MB in size), the server would spend an entire minute trying to compute PBKDF2 on that password. Django's solution is to limit supplied passwords to at most 4KB in size. For this lab, we do not require you to handle such DoS attacks.

## **Part 3: Privilege-separating the bank in Zoobar**

Finally, we want to protect the zoobar balance of each user from adversaries that might exploit some bug in the Zoobar application. Currently, if an adversary exploits a bug in the main Zoobar application, they can steal anyone else's zoobars, and this would not even show up in the Transfer database if we wanted to audit things later.  
To improve the security of zoobar balances, our plan is similar to what you did above in the authentication service: split the zoobar balance information into a separate Bank database, and set up a bank\_svc service, whose job it is to perform operations on the new Bank database and the existing Transfer database. As long as only the bank\_svc service can modify the Bank and Transfer databases, bugs in the rest of the Zoobar application should not give an adversary the ability to modify zoobar balances, and will ensure that all transfers are correctly logged for future audits.

**Exercise 5\.** Privilege-separate the bank logic into a separate bank\_svc service, along the lines of the authentication service. Your service should implement the transfer and balance functions, which are currently implemented by bank.py and called from several places in the rest of the application code.  
You will need to split the zoobar balance information into a separate Bank database (in zoodb.py); implement the bank server by modifying bank-server.py; create the new Bank database and the socket for the bank service, and to set permissions on both the new Bank and the existing Transfer databases accordingly; create client RPC stubs for invoking the bank service; and modify the rest of the application code to invoke the RPC stubs instead of calling bank.py's functions directly.  
Don't forget to handle the case of account creation, when the new user needs to get an initial 10 zoobars. This may require you to change the interface of the bank service.

Finally, we need to fix one more problem with the bank service. In particular, an adversary that can access the transfer service (i.e., can send it RPC requests) can perform transfers from *anyone's* account to their own. For example, it can steal 1 zoobar from any victim simply by issuing a transfer(victim, adversary, 1\) RPC request. The problem is that the bank service has no idea who is invoking the transfer operation. Some RPC libraries provide authentication, but our RPC library is quite simple, so we have to add it explicitly.  
To authenticate the caller of the transfer operation, we will require the caller to supply an extra token argument, which should be a valid token for the sender. The bank service should reject transfers if the token is invalid.  
**Exercise 6\.** Add authentication to the transfer RPC in the bank service. How should the bank validate the supplied token?

**Section 3 : protect your browser**

The zoobar users page has a flaw that allows theft of a logged-in user's cookie from the user's browser, if an attacker can trick the user into clicking a specially-crafted URL constructed by the attacker. Your job is to construct such a URL. An attacker might e-mail the URL to the victim user, hoping the victim will click on it. A real attacker could use a stolen cookie to impersonate the victim.

You will develop the attack in several steps. To learn the necessary infrastructure for constructing the attacks, you first do a few exercises that familiarize yourself with Javascript, the DOM, etc.

**Exercise 1: Remote execution.**

For this exercise, your goal is to craft a URL that, when accessed, will cause the victim's browser to execute some JavaScript you as the attacker has supplied. In particular, for this exercise, we want you to create a URL that contains a piece of code in one of the query parameters, which, due to a bug in zoobar, the "Users" page sends back to the browser. The code will then be executed as JavaScript on the browser. This is known as "Reflected Cross-site Scripting", and it is a very common vulnerability on the Web today.

For this exercise, the JavaScript you inject should call alert() to display the victim's cookies. In subsequent exercises, you will make the attack do more nefarious things. Before you begin, you should restore the original version 

For this exercise, we place some restrictions on how you may develop your exploit. In particular:

* Your attack can not involve any changes to zoobar.  
* Your attack can not rely on the presence of any zoobar account other than the victim's.  
* Your solution must be a URL starting with [http://localhost:8080/zoobar/index.cgi/users?](https://css.csail.mit.edu/6.858/2017/labs/lab4.html).

When you are done, cut and paste your URL into the address bar of a logged in user, and it should print the victim's cookies (don't forget to start the zoobar server: ./zookld). Once it works, put your attack URL in a file named answer-1.txt. Your URL should be the only thing on the first line of the file.

**Hint**: You will need to find a cross-site scripting vulnerability on /zoobar/index.cgi/users, and then use it to inject Javascript code into the browser. What input parameters from the HTTP request does the resulting /zoobar/index.cgi/users page display? Which of them are not properly escaped?

**Hint**: Is this input parameter echoed (reflected) verbatim back to the victim's browser? What could you put in the input parameter that will cause the victim's browser to execute the reflected input? Remember that the HTTP server performs URL decoding on your request before passing it on to zoobar; make sure that your attack code is URL-encoded (e.g. use \+ instead of space, and %2b instead of \+). This [URL encoding reference](http://www.blooberry.com/indexdot/html/topics/urlencoding.htm) and this [conversion tool](http://www.dommermuth-1.com/protosite/experiments/encode/index.html) may come in handy.

**Hint**: The browser may cache the results of loading your URL, so you want to make sure that the URL is always different while your developing the URL. You may want to put a random argument into your url: \&random=\<some random number\>.

**Exercise 2\. Steal cookies.**

Modify the URL so that it doesn't print the cookies but emails them to you. Put your attack URL in a file named answer-2.txt.

Create an attacker server that will keep the session cookie in his database.

The new reflected URL should send the cookie to the evil server

This can be done by java script when you create a new image for instance using new Image().src and put as the source a link to your own server which calls with the stolen cookie as Get query.

**Exercise 3\. protect**

Protect your web page against such attacks without changing the logic of the page\!

You will need to show that the attack does not work the second time around \!

Good Luck ☺

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAVEAAAGpCAYAAAA0twU2AABkx0lEQVR4Xu2dBxQURda2d82sYlbQVTGCiihGzBhQUMAI5lUwK6IoILpmEQVzQBATYsSsYMS06oq4uqsYUBQxgYpZMa2p//PU/re/mpqeme6ZTjNzn3Pumenc1eHtCrdu/clTFEVRquZP7gxFURQlPCqiiqIoNaAiqiiKUgMqooqiKDWgIqooilIDKqKKoig1oCKqKIpSAyqiiqIoNaAiqiiKUgMqooqiKDWgIqooilIDKqKKoig1kKmI/uUvf/H+9Kc/FVklnn/+ee+www5zZ6dGpfPcfffd3Vne/PPPb34fe+wxr1WrVoHWrVu3onm2weDBg/3jL7bYYt4+++xjH6ZuufTSS91ZJo3//ve/3dlKAJWeSZvff//du+aaa9zZqVLqXH/88Ufv0EMPLdCDddZZx1/O9BVXXGH+/+tf//L+85//+MuyIjglKYGIbrTRRt6ECRMKrBI33XRTyZuQBpUe2HIiOnPmTO+SSy4xtsoqq3iLLrqoP3311Vf7/7E2bdoUTAMiet1115nrdNJJJ3kLLrig9/nnn9uHqkv4gLiQ5jlz5rizlQAqPZM2iOh+++3nzk6VUud6xBFHmGUzZszwvvzyS+/666/3ttxyS385z8TLL79s/t92223evffe6y/LiuCUpAQi2qNHD3e24eabb/ZuueUWfxrxIff5xx9/eC1atPBzYphwzjnneCuuuKJZtv322/vzX331Va99+/beaaedZta/8MILvVmzZnkXX3yxN2rUKLP+Ioss4v3666/+Nk8//bSfU95iiy28Bx980F9W6YEtJ6I2W221lbf88su7s3023XRTd5YR0Q8++MCf5roccsgh1hr/x+zZs73+/fv758s1FUifzD/33HML0s61euONN/zl//jHP/xl06ZNM7mYCy64wCxbfPHFzUtp06tXL2+++ebzllhiCW/QoEEFyzhfPhxsu9Zaa5mPAfdq3nnn9e/n9OnTzbpyHkCug2eF7ciV//TTT/4+yZm89NJLRhhYvuaaa/rLeF7kHmN8tN9++21/eaPgPpNcuylTppjrynwRG4SJ68/94Vqvt956/jYPPPCAvx/Eimsn7LXXXt4jjzxilm2wwQbe/vvvb+5bp06dzDz+I3zC3/72N/Nss4x30n6+wD5XG+Yfc8wx7mwf0oUuXHvttUYHeEdJxxlnnGGW//e//zXPs6TjmWeeKdxBAgSnJCXKiehvv/3mLbzwwuaF+uWXX8zNev/9982yPn36mAs0evRoY8CLjFAdf/zx3tixY83Flqz+Cy+8YNZff/31vXHjxpkX8r333vNWX311s97999/vde/e3YirwH/Wfeihh7y1117bPIyC+8C6pCmipKVfv37WGv8HOV2uMS/HPffc45166qlm/j//+U9vgQUWMGKIiJEWilAC023btjXbXXnllUYov/76a7OMa8p123DDDc2Lue2225qcsfDiiy96HTp08MaMGWPOlesmLyPXHAH8+9//bj5KCDxifPfdd5trLPfzq6++8s9DivM8C3/961/NOfXt29fbY489/P3yceScDjzwQJMmrikfSeA47OeOO+7wHn74YW/PPff0Jk+ebJY1Eu4zyX+uCc82uTnuNx8wPj7c04033thca8moSOmOaXkmTj/9dH9/yy67rDGu4Z133ultttlmvnjxjnCfeSaEzp07GyHmuUNQeRZsSr0/Sy+9tDFbwG3Yjo/m66+/7h188MEm50o6qOID3j0+EBMnTvRuuOEGU1LjmUyS4JSkBC84LwYXWYzcpMDNkYfj6KOP9ucHFefJhbhfO3KXiLGIqA0vNC+dDevbUGzgoUJMV1ppJX+++8C68OW104T9+c9/dlerWkTZbscddzQ5Pc6DNLrwUenYsaM728ADb9elPvXUU0Uv4GuvvVYwfdZZZ5n/iOhxxx3nLwPSCwiXe10++ugjI3LA9bVLCDZBxXn2hYj+/PPP3g477FC0bMiQIeY/+ydnLXz44Yfesccea/5z3qxLDqWRcZ9J/pNztKcPP/xw8z+oOM9yBFK47777Cva35JJLFjxniCgfNgGhdu/9xx9/bN4dLOiZKgU5aD62rDPPPPN4AwYM8JcxT+pEg4rzvBNkugRyzOhMkpROSQqUy4kKiCe5FLv4FiSi6667rrfyyisXGOt88803JUX0xBNPLJi30EIL+f/JrciDyZfNfUDd/dkknROluExunDpRu6htQ85RXhoXzv28887zp7lGbvrselamRQgRUXtbWG655czvpEmTzLr2PeDjI7lclpELDaKciFICcXMy3BNyo8C5vfXWW/4yzl0+up999pkpfvLCcwzJ5TYa7jPJ/1deeaVgmpwblBJR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o1BKSIMaQxu9m6yKaBMRJKI2P/zwg/f88897hx12mB/6rJRRz8jQ0ozBE5QjTAoapR599NGSDWvk/rLORbvcdttt/vlRL90IBOVIqQu1PxpijVyUBxXRJqKSiJaDlu077rjDO/nkk80wEe6LYlv79u29Aw44wHvqqacSjXpk+39SFSGuNrbttttu3vXXX+9umjp0nJBI9tisWbPcVeoSEVIEVLCFtNEFFFREm4haRNSFIXSHDh3q7bHHHkXC5RrrELDj448/dndTNUH+nzRKEcdg2WWXLToHuuIOHz7c3U2q0OAn59O6dWvvueeec1epO8iRkh479qxEe8IauS5UUBFtIuIU0XJMmTLFGz16tLfxxhsHRooXo66M3Nm4ceMi3aco/p/08d5mm22Kjk3vL+qBiSubNvRQk/Po16+f9+uvv7qrVMW6665blM5GN/yhs0ZFtIlIS0RtEAhEcsCAAaYe1X0JbKMelvpYRPjHH390d2Wo1v+TrrK2D6cYjVJEZZJ+4GmBb6ycQ+fOnd3FVaEimg0qok1EFiJajk8++cQ40xOcxPbtDDI3QHatLkNTp0411RFu4wi2/PLLew888EAqfrPSFZbxr8hh14KIKHXANK41st16660mrSqiCaIiWkzeRNSFl4PiN76qQf3sxfAFPemkk4zolCvKh4F6WjoaBFU7cBziGCQZ0o3ur4svvrh/zFpizaqIZoOKaBORdxENwo4+Tz2mLThBRjGZqEqTJ082LltRQcTYdu211y7aN0a1RBLxQ+2uku3atXMXh0JFNBtURJuIehNRuwunHf9z5syZxnVm5513LhI52+g8sN9++5kIUtUEA5kxY4YZnC1oIEP2O378eHeTqiFHfdppp/n7f/DBB91VKqIimg0qok1EvYhoLdHn6Q566aWXeh06dAgUPzH65uMihRCGDY+HixLxCFZeeeWi/XE8enPVWr3A87rKKqv4+42Sm1YRzQYV0SaiXkTU9v+spQsnDUNXX321iblKoBVX+GwjUAsCSVQpxLIS+L1usskmRfshYhYeBqW8C8LACACyP+4VoyKEQUU0G1REm4i8iygNRXYAkVpzdeVggLl77rnH69GjR9lRXKkSoI6SkIOPPfaYuxsf4rwecsghgdsTPPv11193N6nI2LFj/f24Y72De31URLNBRbSJyLOI2l04ccKfMGGCu0qi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QeJ3UUW0GBXRdFARVdIg8buoIlqMimg6qIgqaZD4XVQRLUZFNB1URJU0SPwuqogWoyKaDiqiShokfhdFRJvNwohos1naIjp06FBz3AEDBriLMgWHfbkmSv2T+F1UES1GRTQdrr/+enNciUeaFwYNGmTOi27HSv2TuIgqSpYQw1RE3I2RkCZffvml6WMv58LoAXZ4R6V+URFVGhpiKhDcWcSL4DWIWVoCRig9ooYR1d/Olcc5moKSLSqiSlNANC/iIbhVDMSqJTIV1U5E23/44YdNZP8o0A2WkIyIM6Hz1lprraLjYBtuuGFRsBul/lERVZoKwgEecMABRQLnGvWVxE/YddddvV69epkhZBgGhG0RXKoGCLlIwGZ3W9vmmWceE5v1hRdecE9FaRBURJWmhjCJs2bNMkOnnHPOOUYY3WFSKhlxbBlqmcEPGWmBweuU5kFFVFECIFL95MmTjShSp0kOltb+W2+91QRvZtA/Yq9GHSpFaTxURBVFUWpARVRRFKUGVEQVRVFqQEVUURSlBlREFUVRakBFVFEUpQZURBVFUWpARVRRFKUGVEQVRVFqQEVUURSlBlREFUVRakBFVFEUpQZURBVFUWpARVRRFKUGVEQVRVFqQEVUURSlBmIV0enTp6upqallbmkSq4i6wyaoqampZWFpEuvRJAHt2rVTU1NTS90aRkQVRVGyIAsNivVoWSRAURRFyEKDYj1aFglQFEURstCgWI+WRQIURVGELDQo1qNlkQBFURQhCw2K9WhZJEBRFEXIQoNiPVoWCVAURRGy0KBYj5ZFAtLilVde8V566SW1DO2jjz5yb4uiFJCFBsV6tCwSkBZLLbWUnz61bOy4445zb4uiFCDPSprEerQsEpAWIqKrrbaat/HGG6ulaCqiSliy0KBYjxY1AYceeqh38cUX+9M//fSTd8IJJ3gvv/yymT7wwAOL7IorrvDOO+8876CDDvK3E1h+7733urNjQUT0yy+/dBcpCXP55ZeriFqMHTvWfx9OOukk76mnnipY/v777/vLjzrqKO+2224rWA68R5tvvrm3xhpreD169PC+//57d5VU2WOPPbypU6e6syMTVYPiINajRU3AX/7yF3MD4euvv/b+/Oc/e1dffbW/nH0FPQBw4oknehMmTPCnBw0a5D300EPWGvGiIpodKqKFHHHEEeZ9gV9++cUI0OOPP+4v/89//uMNHz7cn77lllv8TMfrr79u3rv33nvPXw4HHHBAwXTaiHagAaSnWqJqUBzEerSoCRAR/fzzz73111/fu/XWWwuWlxNRcq3LLbec99VXX3kvvPCCN88887irxIqKaHaoiBZiiyg8++yz3uDBg/1pV0T/+OMPb8kllzT/yZ0iVC6//fabOytVRDvEqs2ZRtWgOIj1aFETgIhusMEG5nfSpEnuYrMvHo4HHnjAN4oqArlROeYjjzxi5vXr18+IctyoiGaHimghrogec8wx3vjx4/1pV0Q/+eQTU7cMXMeTTz7ZX1YNvK+u6CVlCP6ee+7pnkJJZLs0ifVoURMgNwPhC8K9oNhVV13lLyc3utZaa3mHHHKIPw9XpJ9//tmfjgsV0exQES0EET366KNN+8Gmm25qrs3vv//uL0dEyXFS3TVy5Eivbdu23rhx48wy1r3ooov8dashTRHdaaedTEkzLLJdmsR6tKgJkOI8udGg7ZhXqjgvXHDBBcaHMGlURLNDRbQQOyeKYLZq1cpkKATmnXXWWd7cuXO9X3/91Z8PXMeDDz64YF4ecMUzinDaRNWgOIj1aFETICKKMHXs2NEbM2ZMwXIVUQVURAtxi/M33XSTuUaCW5y3oeRGW0LeEO2ImvN0iapBcRDr0aImwG6dh/bt2xdUerOvK6+80ps9e7Zvc+bM8ZeDK6LUD2mdaGOhIlqIK6LA9bn00kvN/3IiSo6VKgByqtSVwqxZs7wOHTo4a6ZLLcJpE1WD4iDWo0VNgCuin376qflS8mUF2Z9t7s12RVQblhoPFdFCgkS0TZs2XuvWrc3/ciIK3377rbfQQgt58803n8mVcm2HDh3qrlaXRNWgOIj1aFkkIC3iFtEPPvjAuJ7UI+RgXn311YJ51L0xjw/hm2++6c2YMaNgeS2oiCphyUKDYj1aFglIi7hFdL/99vNbVPGHmzJlirNGfsFFxr7PN998s/FDZB7FxJVWWskUGeNCRVQJSxYaFOvRskhAWsQtojZbb721XxSrR7gu5YqPtaIiqoQlCw2K9WhZJCAtqhXRL774wuvVq5fXvXt37/zzzzfFXcCHT4rzyy+/vNeiRQuvf//+xgQ6EODvd+SRR3ovvviiPz+I1157zevZs6epY77++utNd0DqhkeMGOG99dZbpg/18ccf73344YcF29FT5W9/+5vZjro0G87v+eefN8t69+5tqiDg6aefNvuFu+66y1wX0ifzRo8e7ddrA642nBPrHHbYYUVuN5VQEVXCkoUGxXq0LBKQFtWIKJ4F9vUgyIO0iNrF+aCcKL2xHn74YfMfodt3331L1jPusssupqFAoLWVDgf0k+b4d9xxh5n/9ttve4sttpi/HoK9wAIL+NO77767N++88/rTbDtkyBB/+t133zW/bnGe/7YDt12c59yXWGKJAoGOGuxCRVQJSxYaFOvRskhAWlQjohRxS12PciKK8OBAbfPOO++ULDJvt9123iKLLOLO9kXUBnGePn26+Y+42dGwaBiS9cmF0uJr94QRoogoEYbIgdeCiqgSliw0KNajZZGAtKhGRIGWanEj2Xvvvf1cWDkR/ec//2nWb9euXYFJUV+us329J06c6C288MIFghYkoojaqFGjzH+WIdbucWDmzJkFuVCbKCJK18RaI9KriCphyUKDYj1aFglIi2pFFMjVIaZsP2zYMDOvnIhOmzatqutIPSj1lWxLHWqQiBIW7fbbbzf/WXbJJZcULBe++eYbb5999nFnG6KIKLFf+SjUgoqoEpYsNCjWo2WRgLSoRkTpCHDjjTea/wgm20uR3BbRgQMHmmWIHmIL1113nWmEIWoVIkx9pNRJutBoJFGwaMRhX//+9799EWX5d99951177bUFPcIITsFyySlSZyoiDyzr3Lmz+c+5Sh1tFBEFjilFehy9aWyLgoqoEpYsNCjWo2WRgLSoRkQJ9MA21D3S+k6/4KDiPEVnury612/RRRc101JMZ70g/vrXv5rl+GrSCwVfTRARXWeddbwFF1zQ/N9oo4387RDnc88919+WX9Ip0KLOfDn/M88808yPKqK77babfwzivn788cf+sjCoiCphcd+hNIj1aFkkIC2qEdGsCSrO1yMqokpYstCgWI+WRQLSQkU0O5pRRMm9uzAEDhBEhP7zQUZDnjvPNsD3d/vttzdGBHmqdbKG6qc43q0sNCjWo2WRgLSoRxFtFJpRRGU4DxtEz+WUU04p+86x7L///W/BPEaIsDtD3HDDDd6AAQOsNdLnH//4h28IarVkoUGxHi2LBKSFimh2qIj+j6REFL9koqdliS2iIqTVvGtZaFCsR8siAWmhIpodzSiihIlk5Fvb1lxzTXe1WEQUFzR6xIXlmWeeKRK9JE2G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>