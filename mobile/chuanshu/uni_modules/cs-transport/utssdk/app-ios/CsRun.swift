import Foundation

/** The two queues this plugin's UTS half runs on.
 *
 *  Android gets `UTSAndroid.getDispatcher('io')` for free and Harmony has no I/O thread at all, so the
 *  page's callbacks arrive on whatever thread the socket woke up on. Here that has to be said out loud:
 *  a request blocks on a semaphore until the peer answers, and a block on the main queue is a frozen
 *  screen - so the work goes to a concurrent queue and only the answer comes back to the main one.
 *
 *  Concurrent, not serial: a sender that keeps a 180-second `finalize` open must not be the reason a
 *  chunk request cannot start, and the state machine inside `CsServe` has its own lock for the parts
 *  that genuinely cannot overlap. */
public enum CsRun {

    private static let io = DispatchQueue(label: "com.chuanshu.io", attributes: .concurrent)

    public static func background(_ body: @escaping () -> Void) {
        io.async { body() }
    }

    public static func main(_ body: @escaping () -> Void) {
        DispatchQueue.main.async { body() }
    }
}
