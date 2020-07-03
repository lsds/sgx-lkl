public class SimpleThread extends Thread {
	private Thread t;
	private String threadName;
	private SharedData sharedData;
	
	public SimpleThread(String name, SharedData data) {
		threadName = name;
		sharedData = data;
	}
	
	public void run() {
		synchronized(sharedData) {
			sharedData.incrementCounter();
		}
		
		System.out.printf("Thread %s is completed successfully\n", threadName);
	}
	
	public void start() {
		System.out.printf("Starting thread %s\n", threadName);
		if (t == null) {
			t = new Thread(this, threadName);
			t.start();
		}
	}
	
	public void waitThreadToFinish() throws InterruptedException {
		if (t != null) {
			t.join();
		}
	}
}
