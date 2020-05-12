import java.io.*;
import java.nio.file.*;
import java.util.stream.*;
import java.nio.charset.*;

public class FileReadSample {
	public  String readFile(String filePath) throws IOException {
		StringBuilder contentBuilder = new StringBuilder();
		Stream<String> stream = Files.lines( Paths.get(filePath), StandardCharsets.UTF_8);
		stream.forEach(s -> contentBuilder.append(s).append("\n"));
		return contentBuilder.toString();
	}
}
