#include <iostream>
#include <omp.h>
#include <stdio.h>

using namespace std;

#define NUM_THREADS 8

void init_array(float * array, int sz, float value) {
    for (int i = 0; i < sz; i++) {
        array[i] = value;
    }
}

void dump_array(float * array, int sz) {
    for (int i = 0; i < sz; i++) {
        cout << array[i] << " ";
        if (!((i+1) % 16)) {
            cout << endl;
        }
    }
    cout << endl;
}

int main(int argc, char const * argv[]) {

    const int count = 64;

    float a[count] = {};
    float b[count] = {};
    float c[count] = {};

    omp_set_num_threads(NUM_THREADS);

    //int numthreads = omp_get_num_threads();
    int numthreads = omp_get_max_threads();
    printf("Running with following number of threads: %d\n", numthreads);

#pragma omp parallel for num_threads(NUM_THREADS)
    for (int t =0; t < numthreads; ++t) {
        printf("Hello from thread: %d\n", omp_get_thread_num() );
    }

    init_array(a, count, 21.0f);
    init_array(b, count, 2.0f);
    init_array(c, count, -10101.0f);

#pragma omp parallel for num_threads(NUM_THREADS)
    for (int i = 0; i < count; i++) {
        c[i] = a[i] * b[i];
    }

    dump_array(c, count);

    return 0;
}
