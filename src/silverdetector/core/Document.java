package silverdetector.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The blob of text you pasted, plus line numbers so findings can point back at it.
 */
public final class Document {

    /** One physical line of the pasted input. {@code number} is 1-based, like an editor shows it. */
    public record Line(int number, String text) {

        public String trimmed() {
            return text.trim();
        }

        public boolean isBlank() {
            return text.trim().isEmpty();
        }

        /** Lines starting with '#' are treated as your own annotations, not data. */
        public boolean isComment() {
            return trimmed().startsWith("#");
        }
    }

    private final String source;
    private final String raw;
    private final List<Line> lines;

    private Document(String source, String raw, List<Line> lines) {
        this.source = source;
        this.raw = raw;
        this.lines = List.copyOf(lines);
    }

    public static Document of(String source, String raw) {
        String normalised = raw.replace("\r\n", "\n").replace('\r', '\n');
        List<Line> parsed = new ArrayList<>();
        int number = 1;
        for (String text : normalised.split("\n", -1)) {
            parsed.add(new Line(number++, text));
        }
        // split() with a trailing newline leaves one empty line at the end; drop it.
        if (!parsed.isEmpty() && parsed.get(parsed.size() - 1).text().isEmpty()) {
            parsed.remove(parsed.size() - 1);
        }
        return new Document(source, normalised, parsed);
    }

    public static Document fromFile(Path path) throws IOException {
        return of(path.toString(), Files.readString(path, StandardCharsets.UTF_8));
    }

    public static Document fromStream(String source, InputStream in) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = in.read(chunk)) != -1) {
            buffer.write(chunk, 0, read);
        }
        return of(source, buffer.toString(StandardCharsets.UTF_8));
    }

    public String source() {
        return source;
    }

    public String raw() {
        return raw;
    }

    public List<Line> lines() {
        return lines;
    }

    /** Everything a detector should look at: no blanks, no '#' notes of your own. */
    public List<Line> contentLines() {
        List<Line> out = new ArrayList<>();
        for (Line line : lines) {
            if (!line.isBlank() && !line.isComment()) {
                out.add(line);
            }
        }
        return out;
    }

    public int lineCount() {
        return lines.size();
    }

    public boolean isEmpty() {
        return contentLines().isEmpty();
    }
}
