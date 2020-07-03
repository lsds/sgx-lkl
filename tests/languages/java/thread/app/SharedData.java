// This is sample shared object that threads call increment method
public class SharedData {
	private int counter = 0;
	
	public int getCounter() {
		return counter;
	}
	
	public void incrementCounter() {
		counter++;
	}
}
