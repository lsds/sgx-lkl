import java.io.*;

public class MainApp
{
	public static void main(String[] args) throws IOException {
		System.out.println("Hello SGX world from MainApp Java!");
		FileReadSample frs = new FileReadSample();
		System.out.println("Trying to read file /app/input.txt");
		String data = frs.readFile("/app/input.txt");

		System.out.println("Content of the file:");
		System.out.println(data);
		
		if (data.compareTo("This is the first line of the file\nThis is the second line of the file\n") != 0) {
		    System.exit(1);
		} 
	}
}
