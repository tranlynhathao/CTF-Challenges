#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 1200
#define MAX_BYTES 512

static int trace_unsealed = 0;

static void trim_newline(char *s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
    s[n - 1] = '\0';
    n--;
  }
}

static int hex_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  return -1;
}

static int parse_hex(const char *in, uint8_t *out, size_t *out_len) {
  size_t start = 0;
  size_t n = strlen(in);
  if (n >= 2 && in[0] == '0' && (in[1] == 'x' || in[1] == 'X'))
    start = 2;
  if (((n - start) % 2) != 0)
    return 0;
  if ((n - start) / 2 > MAX_BYTES)
    return 0;
  *out_len = 0;
  for (size_t i = start; i < n; i += 2) {
    int hi = hex_value(in[i]);
    int lo = hex_value(in[i + 1]);
    if (hi < 0 || lo < 0)
      return 0;
    out[(*out_len)++] = (uint8_t)((hi << 4) | lo);
  }
  return 1;
}

static void banner(void) {
  puts("EggRoll Vault Gateway");
  puts("gateway: orchard-vault-debug");
  puts("status : calldata echo window online");
  puts("note   : sealed notes are indexed by the web oracle");
}

static void submit_calldata(void) {
  char line[MAX_LINE];
  uint8_t buf[MAX_BYTES];
  size_t len = 0;

  printf("hex calldata> ");
  if (!fgets(line, sizeof(line), stdin))
    return;
  trim_newline(line);

  if (!parse_hex(line, buf, &len) || len < 6) {
    puts("calldataEcho: malformed envelope");
    return;
  }

  uint32_t selector = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) | ((uint32_t)buf[2] << 8) | buf[3];
  uint16_t declared_len = ((uint16_t)buf[4] << 8) | buf[5];
  uint8_t echo_window = (uint8_t)declared_len;
  size_t actual = len - 6;

  printf("calldataEcho.selector = 0x%08x\n", selector);
  printf("calldataEcho.declared = %u\n", declared_len);
  printf("calldataEcho.window   = %u\n", echo_window);

  /*
   * intentional CTF vulnerability:
   * The ABI layer records a 16-bit declared length, but the debug echo layer
   * later trusts the truncated 8-bit window. A crafted envelope can make the
   * short echo path accept a longer declared payload and open trace mode.
   */
  if (selector == 0xea600d01 && declared_len > 255 && echo_window == actual) {
    const char magic[] = "orchard-gateway:trace:";
    if (actual >= strlen(magic) && memcmp(buf + 6, magic, strlen(magic)) == 0) {
      trace_unsealed = 1;
      puts("calldataEcho: trace window staged");
      return;
    }
  }

  puts("calldataEcho: queued for normal settlement");
}

static void encrypted_note(void) {
  puts("sealedNote.index = vaultTrace.sealedNote");
  puts("sealedNote.source = GET /api/oracle");
  puts("sealedNote.state = encrypted");
}

static void debug_trace(void) {
  if (!trace_unsealed) {
    puts("vaultTrace: sealed");
    puts("vaultTrace: submit a matching calldata envelope first");
    return;
  }

  puts("vaultTrace: opened");
  puts("rollup.slot[0] = 0x0000000000000000000000000000000088421");
  puts("rollup.slot[1] = 0xe16b00b5d2ca5a3a2d66ed68055a87df");
  puts("rollup.slot[2] = 0x4f7263686172642d476174657761792d7632");
  puts("rollup.slot[3] = 0x9b779cd97f02db0119dce3bf3a14a86d");
  puts("rollup.slot[4] = 0x00000000000000000000000000000130");
  puts("rollup.slot[5] = 0xa2d7c11605fd4a8994f428b3bd4ac71f");
  puts("rollup.slot[7] = "
       "0xb0e92c9d607f69198e087d8f89763467e61d8066602d58099977df1ba14f48573169e958701a8c068a5c5a56bb3802338bb6d50d1ef00"
       "8");
  puts("rollup.slot[8] = 0x31d63fb7a74b6fd715f4312b9d837de3");
  puts("rollup.slot[9] = 0x00000000000000000000000000000040");
}

static void menu(void) {
  puts("");
  puts("1. show vault banner");
  puts("2. submit calldata");
  puts("3. get encrypted note");
  puts("4. debug trace");
  puts("5. exit");
  printf("> ");
}

int main(void) {
  char line[64];
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  banner();
  while (1) {
    menu();
    if (!fgets(line, sizeof(line), stdin))
      break;
    int choice = atoi(line);
    switch (choice) {
    case 1:
      banner();
      break;
    case 2:
      submit_calldata();
      break;
    case 3:
      encrypted_note();
      break;
    case 4:
      debug_trace();
      break;
    case 5:
      puts("bye");
      return 0;
    default:
      puts("unknown option");
      break;
    }
  }
  return 0;
}
