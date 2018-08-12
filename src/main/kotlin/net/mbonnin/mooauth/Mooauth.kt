package net.mbonnin.mooauth

import fi.iki.elonen.NanoHTTPD
import java.io.File
import java.security.SecureRandom


/**
 * Mooauth will open authorizeUrl in a browser and listen to potential redirects once the user logs in
 * You must configure your oauth app with a redirect_uri set to http://localhost:port
 *
 * @param authorizeUrl: the url to open in a browser in the form https://github.com/login/oauth/authorize?client_id=[..]&scope=[..]&state=[..]&redirect_uri=[..]
 * @param exchangeCode: a callback to exchange the code for a valid token. This will be called from a thread
 * @param httpPort: the port where the server will listen
 */
class Mooauth(val authorizeUrl: String,
              val exchangeCode: (uri: String) -> String,
              val httpPort: Int = 8941) {
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
        var token: String? = null

        System.out.println("acquiring oauth token")

        val server = object : NanoHTTPD(httpPort) {
            override fun serve(session: IHTTPSession): Response {
                val result = exchangeCode(session.queryParameterString)

                synchronized(lock) {
                    lock.notify()
                }

                return newFixedLengthResponse(result)
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