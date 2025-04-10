#include <inttypes.h>
#include <stdio.h>

#define BUF_SIZE 20

typedef struct LogRecord {
  uint64_t insn_count;
  char cpu;
  char store;
  uint64_t address;
} LogRecord;

int main() {

  LogRecord buf[BUF_SIZE];
  FILE *file = fopen("logs/firefox/merged.log", "r");

  int found = 0;
  uint64_t insn = 0;
  uint64_t prev_count = 0;
  uint64_t prev_cpu = -1;
  while (!found) {
    fread(&buf, sizeof(LogRecord), BUF_SIZE, file);
    for (int i = 0; i < BUF_SIZE; ++i) {
      if (buf[i].insn_count < prev_count) {
        printf("SHIT\n");
        printf("prev count: %" PRIu64 "\n", prev_count);
        printf("%" PRIu64 ",%d,%d,%016" PRIx64 "\n", buf[i].insn_count,
               buf[i].cpu, buf[i].store, buf[i].address);
      }
      ++insn;
      prev_count = buf[i].insn_count;
    }
  }
  return 0;
}
