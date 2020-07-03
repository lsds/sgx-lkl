import java.io.*;
import java.net.*;

public class MainApp
{
	public static void main(String[] args) throws MalformedURLException {
		URL url = new URL("https://www.microsoft.com/");
		
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream(), "UTF-8"))) {
			for (String line; (line = reader.readLine()) != null;) {
				System.out.println(line);
			}
		} catch(Exception e) {
			System.out.println(e);
			System.exit(1);
		}
	}

}
