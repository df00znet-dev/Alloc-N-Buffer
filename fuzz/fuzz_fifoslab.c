#include "fifoslab.h"
#include <stdint.h>
#include <stddef.h>

/*
 * libFuzzer harness for ANB_FifoSlab.
 *
 * Interprets fuzz input as a stream of commands:
 *   0 = push_item   (next 2 bytes = length LE, then that many bytes = data)
 *   1 = pop_item
 *   2 = peek_item   (next 1 byte  = index)
 *   3 = item_count
 *   4 = peek_item_iter (iterate all items from the start)
 *   5 = size
 *
 * Goal: no crashes, no ASAN/UBSAN violations under any input.
 */

static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ANB_FifoSlab_t *q = ANB_fifoslab_create(64);

    size_t i = 0;
    while (i < size) {
        uint8_t cmd = data[i++] % 6;

        switch (cmd) {
        case 0: { /* push_item */
            if (i + 2 > size) goto done;
            uint16_t len = read_u16(data + i);
            i += 2;
            /* Cap push size to avoid OOM killing the fuzzer */
            if (len > 4096) len = 4096;
            if (len == 0) break;
            if (i + len > size) len = (uint16_t)(size - i);
            ANB_fifoslab_push_item(q, data + i, len);
            i += len;
            break;
        }
        case 1: { /* pop_item */
            ANB_fifoslab_pop_item(q);
            break;
        }
        case 2: { /* peek_item */
            if (i + 1 > size) goto done;
            uint8_t idx = data[i++];
            size_t item_size = 0;
            volatile uint8_t *p = ANB_fifoslab_peek_item(q, idx, &item_size);
            if (p) { (void)*p; }
            break;
        }
        case 3: { /* item_count */
            ANB_fifoslab_item_count(q);
            break;
        }
        case 4: { /* peek_item_iter — iterate all items */
            ANB_FifoSlabIter_t iter = {0};
            size_t item_size = 0;
            volatile uint8_t *p;
            while ((p = ANB_fifoslab_peek_item_iter(q, &iter, &item_size)) != NULL) {
                (void)*p;
            }
            break;
        }
        case 5: { /* size */
            ANB_fifoslab_size(q);
            break;
        }
        }
    }

done:
    ANB_fifoslab_destroy(q);
    return 0;
}
