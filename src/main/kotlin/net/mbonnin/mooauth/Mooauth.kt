package net.mbonnin.mooauth

import fi.iki.elonen.NanoHTTPD
import java.io.File
import java.security.SecureRandom


/**
 * Mooauth will open authorizeUrl in a browser and listen to potential redirects once the user logs in
 *
 * @param authorizeUrl: the url to open in a browser
 * @param exchangeCode: a callback to exchange the code for a valid token. This will be called from a thread
 */
class Mooauth(val authorizeUrl: String, val exchangeCode: (state: String, code: String) -> String) {
    private val lock = java.lang.Object()

    fun randomString(len: Int): String {
        val sb = StringBuilder(len)
        val AB = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        val rnd = SecureRandom()

        for (i in 0 until len)
            sb.append(AB[rnd.nextInt(AB.length)])

        return sb.toString()
    }

    fun authorize() {
        val state = randomString(16)
        var token: String? = null

        System.out.println("acquiring oauth token")

        val server = object : NanoHTTPD(8941) {
            override fun serve(session: IHTTPSession): Response {
                if (session.parms["state"] != state) {
                    return newFixedLengthResponse("bad state $state")
                }
                val code = session.parms["code"]
                if (code == null) {
                    return newFixedLengthResponse("bad code $code")
                }

                val result = exchangeCode(state, code)

                synchronized(lock) {
                    lock.notify()
                }

                return newFixedLengthResponse("yay, you've been authorized !")
            }
        }

        server.start()

        openBrowser(authorizeUrl)

        synchronized(lock) {
            while (token == null) {
                lock.wait(1000)
            }
        }

        // sorry guys, no better solution than sleep until the response is sent
        // see https://github.com/NanoHttpd/nanohttpd/issues/355
        Thread.sleep(2000)

        server.stop()
    }

    private fun openBrowser(url: String) {
        val candidates = arrayOf("xdg-open", "open")

        val found = candidates.filter({ isInPath(it) })

        if (found.isEmpty()) {
            throw Exception("cannot open browser for github oauth")
        }

        Runtime.getRuntime().exec(arrayOf(found[0], url))
    }

    private fun isInPath(cmd: String): Boolean {
        val pathList = System.getenv("PATH").split(":").map { it.trim() }

        return pathList.firstOrNull { File(it, cmd).exists() } != null
    }
}