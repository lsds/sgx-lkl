public class MainApp
{
	public static void main(String[] args)
	{
		System.out.println("Hello SGX world from MainApp Java!");
		FileReadSample frs = new FileReadSample();
		System.out.println("Trying to read file /app/input.txt");
		String data = frs.readFile("/app/input.txt");

		System.out.println("Content of the file:");
		System.out.println(data);
		
		if (data.compareTo("This is the content of file\n") == 0) {
		    System.out.println("TEST_PASSED");
		} else {
		    System.out.println("TEST_FAILED");
		}
	}
}
