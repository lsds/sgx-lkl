import java.io.*;
import java.nio.file.*;
import java.util.stream.*;
import java.nio.charset.*;

public class FileReadSample {
	public  String readFile(String filePath) {
	StringBuilder contentBuilder = new StringBuilder();
		try (Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8)) 
		{
			stream.forEach(s -> contentBuilder.append(s).append("\n"));
		}
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		return contentBuilder.toString();
	}
}
