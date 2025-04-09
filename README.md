# StackTracer

This is a class that can capture a stack trace for the current thread.

It captures both the native stack trace and the managed stack trace.

It can return the stack traces as plain text (`StackReport.Create`), or as a
script (`StackReport.CreateScript`) that can be executed to print a
symbolicated version of the native stack trace. In the latter case, if
executed on iOS, the script must be copied to the corresponding Mac for
execution.
