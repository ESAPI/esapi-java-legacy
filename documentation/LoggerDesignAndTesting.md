(Gleaned from an email from Jeremiah J. Stacey to Kevin W. Wall on 2021-03-21.  Some minor alterations were made for contextual understanding by Kevin Wall because the original email thread was not included.)

The testing (for SLF4J logging at least) is tested with Mockito and Powermock.  For the SLF4J logging, the tests are in Slf4JLoggerTest.  It uses mocks to assert that the slf4j logging implementation gets the data we expect in the calls we support.

I was very deliberate in the breakout of the classes to isolate specific functionality to enable this type of testing.  At a high level, there are four classes that make up the logging structure.
I tried to encapsulate a subset of functionality into each one:

**LogFactory** - Constructs Loggers to be used by clients.  Responsible for building the LogBridge and the LevelHandler.

**Logger** - The ESAPI interface implementation which uses the LogBridge and a delegate Logger to forward events to the underlying log implementation.

**LogBridge** - Logical handler for determining the delegate handler for a known ESAPI log event, and forwarding the Log event to that handler.  Also responsible for prefixing the client/server info content and applying the newline replacement behavior.

**LogLevelHander** - This is actually where the log event gets sent to SLF4J!  The Handler enumeration is assembled as part of a map in the static block of the LogFactory, and is used by the LogBridge to route a log event at a defined ESAPI log level to the correct API of the delegate Logger.


The general workflow is:

    LogFactory static block creates the LogPrefixAppender, LogScrubber, and LogBridge.

    LogFactory.getLogger(...)  Creates Logger with the delegate slf4j logger implementation and the LogBridge.

    Logger.info/warn/etc(message) -> forwards to LogBridgelog(logger, esapiLevel, type, message) -> forwards to LogHandler.log(...) -> forwards to slf4j Logger implementation with appropriate level and composed message.

So each of the tests for each of the classes verifies data in -> data out based on the Logging API.  The structure for JUL, Log4J, and SLF4J are almost identical.  There are a few differences in the interaction with the underlying Logger interactions and expectations.  As a result, the tests are also almost full duplications (again accounting for differences in the underlying logging API).

-J
