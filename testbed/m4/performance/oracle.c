/* Independent sequential generator for utcp-bulk's seed-1 byte stream.
 * Pipe to sha256sum. No TCP app, library, or payload files are involved. */
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] < '0' || argv[1][0] > '9')
        return 2;
    char *end;
    errno = 0;
    uint64_t remaining = strtoumax(argv[1], &end, 10);
    if (errno || *end)
        return 2;

    uint64_t sequence = 1;
    unsigned char buffer[65536];
    while (remaining > 0) {
        size_t length = remaining < sizeof buffer ? (size_t)remaining : sizeof buffer;
        for (size_t n = 0; n < length; n += 8) {
            uint64_t word = sequence;
            sequence += UINT64_C(0x9e3779b97f4a7c15);
            word = (word ^ (word >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
            word = (word ^ (word >> 27)) * UINT64_C(0x94d049bb133111eb);
            word ^= word >> 31;
            for (size_t m = n; m < n + 8 && m < length; ++m) {
                buffer[m] = (unsigned char)word;
                word >>= 8;
            }
        }
        if (fwrite(buffer, 1, length, stdout) != length)
            return 1;
        remaining -= length;
    }
    return fflush(stdout) == EOF;
}
