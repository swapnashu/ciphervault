package com.sellerbot.ciphervault.sync

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response

/**
 * The uniform error body is where the old-server experience gets fixed: a
 * missing route must never surface the server's raw "No such endpoint".
 */
class VaultApiExceptionTest {

    private fun json404(body: String): Response<Void> =
        Response.error(404, body.toResponseBody("application/json".toMediaType()))

    @Test
    fun `a not_found 404 is reported as a server version problem`() {
        val e = VaultApiException.from(
            json404("""{"error":"not_found","message":"No such endpoint"}"""),
        )

        assertEquals(404, e.code)
        assertEquals("not_found", e.error)
        assertTrue("friendly message: " + e.message, e.message.contains("Not supported"))
        assertTrue(e.message.contains("Update the server"))
    }

    @Test
    fun `other 404 errors keep the server message`() {
        val e = VaultApiException.from(
            json404("""{"error":"conflict","message":"Vault was modified elsewhere"}"""),
        )

        assertEquals("Vault was modified elsewhere", e.message)
    }

    @Test
    fun `a 404 with no json body keeps the default message`() {
        val e = VaultApiException.from(
            Response.error<Void>(404, "Not Found".toResponseBody("text/plain".toMediaType())),
        )

        assertEquals("Request failed (HTTP 404)", e.message)
    }
}
