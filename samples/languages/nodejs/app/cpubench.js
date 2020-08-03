const { fib, dist } = require('cpu-benchmark')

console.log('Hello world from Node.JS from inside an SGX enclave!')

const dur = fib(42) 
console.log('time: ' + dur)

const ops = dist(1000) 
console.log('operations: ' + ops)
