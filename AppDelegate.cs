namespace StackTracer;

[Register ("AppDelegate")]
public class AppDelegate : NSApplicationDelegate {
	public override void DidFinishLaunching (NSNotification notification)
	{
		// Insert code here to initialize your application

		var report = StackReport.Create ();
		Console.WriteLine (report);

	}

	public override void WillTerminate (NSNotification notification)
	{
		// Insert code here to tear down your application
	}
}
