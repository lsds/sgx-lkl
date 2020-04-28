import tensorflow as tf

hello = tf.constant("Hello TensorFlow (from an SGX-LKL-OE enclave)!")
sess = tf.Session()
print(sess.run(hello))
