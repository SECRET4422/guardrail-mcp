// INTENTIONAL INSECURE FIXTURE — demo/test only.
import java.io.ObjectInputStream;
import java.sql.Statement;

public class App {
    void bad(Statement st, String id) throws Exception {
        st.executeQuery("SELECT * FROM t WHERE id=" + id);
        Runtime.getRuntime().exec("ls " + id);
        new ObjectInputStream(null).readObject();
    }
}
