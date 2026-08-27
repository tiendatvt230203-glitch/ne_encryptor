#include "core/flow/flow_table.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void check_ratio(const int weights[2], int packets,
                        int expected0, int max_run)
{
    const int wans[2] = { 0, 1 };
    int count[2] = { 0, 0 };
    int last = -1;
    int run = 0;
    int longest = 0;

    for (int i = 0; i < packets; i++) {
        int wan = flow_table_pick_wan_per_flow_packet(
            0x0a000001u, 0x0a000002u,
            (uint16_t)(10000 + weights[0]), 5201, 17,
            wans, weights, 2);

        assert(wan == 0 || wan == 1);
        count[wan]++;
        if (wan == last)
            run++;
        else {
            last = wan;
            run = 1;
        }
        if (run > longest)
            longest = run;
    }
    assert(count[0] == expected0);
    assert(count[1] == packets - expected0);
    assert(longest <= max_run);
}

int main(void)
{
    const int equal[2] = { 50, 50 };
    const int seventy[2] = { 70, 30 };
    const int five_one[2] = { 5, 1 };
    const int one_wan[1] = { 7 };
    const int one_weight[1] = { 100 };

    check_ratio(equal, 1000, 500, 1);
    check_ratio(seventy, 1000, 700, 3);
    check_ratio(five_one, 600, 500, 5);
    for (int i = 0; i < 100; i++)
        assert(flow_table_pick_wan_per_flow_packet(
                   1, 2, 3, 4, 17, one_wan, one_weight, 1) == 7);

    puts("wan smooth scheduler: ok");
    return 0;
}
