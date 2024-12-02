#include <stdio.h>

unsigned char packet[0x100000000] = {0};


int main(){
    char *p = packet;
    // destination mac
    memcpy(p, "\x00\x0c\x29\x3e\xa1\x2a", 6);
    p = p + 6;
    // source mac
    memcpy(p, "\x00\x15\x5d\x92\x2a\x02", 6);
    p = p + 6;
    // source ip
    memcpy(p, "\xfe\x80\x00\x00\x00\x00\x00\x00\x62\xf7\x63\xa1\x21\x9c\xca\xdf", 16);
    // destination  ip
    memcpy(p, "\xfe\x80\x00\x00\x00\x00\x00\x00\xe8\xe5\x4e\x55\xe0\x22\x58\x59", 16);
    return 0;
}