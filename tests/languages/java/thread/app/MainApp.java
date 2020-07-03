public class MainApp
{
	private static final int THREAD_COUNT = 10;

	public static void main(String[] args) throws InterruptedException {
		SharedData counter = new SharedData();
		System.out.printf("Counter is %d before calling threads.\n", counter.getCounter());   
		System.out.printf("Each thread will increment counter by 1.\n");   

		System.out.printf("Creating and running %d threads.\n", THREAD_COUNT);
		SimpleThread[] threads = new SimpleThread[THREAD_COUNT];
		// Create and start threads
		for (int i=0; i<threads.length; i++) {
			threads[i] = new SimpleThread(String.format("Thread-%d", i+1), counter);
			threads[i].start();
		}
		
		// Wait all threads to finish
		for (int i=0; i<threads.length; i++) {
			threads[i].waitThreadToFinish();
		}
		
		System.out.printf("Counter is %d after all %d threads completed\n", counter.getCounter(), THREAD_COUNT);
		if (counter.getCounter() != THREAD_COUNT) {
			System.out.printf("Counter is %d. Expected value: %d\n", counter.getCounter(), THREAD_COUNT);    
			System.exit(1);
		}
	}
}
