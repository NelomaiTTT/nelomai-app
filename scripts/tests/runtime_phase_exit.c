/* Disposable macOS process-fault instrumentation. No product source hook.
 * Intercept the actual atomic journal publication and exit only after proving
 * the requested durable phase exists. The runner checks exit91 and the journal.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

static int phase_rename(const char *from, const char *to) {
    int result = rename(from, to);
    const char *phase = getenv("NELOMAI_TEST_EXIT_PHASE");
    if (result == 0 && phase && strstr(to, "/common/runtime-switch-v1.json")) {
        int fd = open(to, O_RDONLY);
        if (fd >= 0) {
            char bytes[262145], expected[96];
            ssize_t size = read(fd, bytes, sizeof(bytes)-1);
            close(fd);
            if (size > 0) {
                bytes[size] = 0;
                snprintf(expected, sizeof(expected), "\"phase\":\"%s\"", phase);
                if (strstr(bytes, expected)) {
                    char directory[4096];
                    snprintf(directory, sizeof(directory), "%s", to);
                    *strrchr(directory, '/') = 0;
                    fd = open(directory, O_RDONLY);
                    if (fd < 0 || fsync(fd) != 0) _exit(92);
                    close(fd);
                    _exit(91);
                }
            }
        }
    }
    return result;
}
__attribute__((used)) static struct { const void *replacement; const void *original; }
interpose __attribute__((section("__DATA,__interpose"))) = { (const void *)phase_rename, (const void *)rename };
