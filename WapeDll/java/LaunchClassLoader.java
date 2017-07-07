import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Hashtable;

public final class LaunchClassLoader extends ClassLoader {
  private static LaunchClassLoader instance; // provided by native code
  public static int key;

  private LaunchClassLoader(final ClassLoader parent) {
    super(parent);
    if (instance != null) {
      throw new AssertionError();
    }
  }

  @Override public InputStream getResourceAsStream(String name) {
    final byte[] resourceBytes = findClassBytes(name);
    if (resourceBytes != null) {
      return new ByteArrayInputStream(resourceBytes);
    }
    return null;
  }

  @Override protected Class<?> findClass(String name) throws ClassNotFoundException {
    final byte[] classBytes = findClassBytes(name);
    if (classBytes == null) {
      throw new ClassNotFoundException();
    }
    return super.defineClass(name, classBytes, 0, classBytes.length);
  }

  private native byte[] findClassBytes(final String name);

  // Wape specific methods
  public native static void fl();
  public native static void del(final String[] strings);
  public native static void r(Object r);
}
