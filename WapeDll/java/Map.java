import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

public class Map implements Callable<Void> {
  @Override public Void call() throws Exception {
    Object a = a();
    c(a).invoke(a);
    return null;
  }

  private static Object a() throws Exception {
    return Class.forName("net.minecraft.client.Minecraft")
        .getDeclaredMethod("func_71410_x") // getMinecraft (public)
        .invoke(null);
  }

  private static Object b(Object a) throws Exception {
    Field b = a.getClass().getDeclaredField("field_152351_aB"); // scheduledTasks (private)
    b.setAccessible(true);
    return b.get(a);
  }

  private static Method c(Object a) throws Exception {
    return a.getClass()
        .getDeclaredMethod("func_110436_a"); // refreshResources (public)
  }

  public static void r() throws Exception {
    Object a = a();
    Queue<FutureTask<?>> b = (Queue<FutureTask<?>>)b(a);
    // should synchronize on the ref obj
    synchronized (b) {
      b.add(new FutureTask<>(new Map()));
    }
  }
}
