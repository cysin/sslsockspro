package io.github.cysin.sslsockspro.engine

import org.junit.Assert.*
import org.junit.Test

/** Examples from OpenVPN's management-notes.txt. */
class OpenVpnManagementTest {
    @Test fun dynamicChallengesAreParsed() {
        val challenge = OpenVpnManagement.dynamicChallenge(
            ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN']")!!
        assertEquals(OpenVpnManagement.Companion.Dynamic(true, true, "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l", "cr1", "Please enter token PIN"), challenge)
        assertNull(OpenVpnManagement.dynamicChallenge(">PASSWORD:Verification Failed: 'Auth'"))
    }

    @Test fun staticChallengesCombineThePasswordAndCode() {
        assertEquals(1 to "Please enter token PIN", OpenVpnManagement.staticChallenge(">PASSWORD:Need 'Auth' username/password SC:1,Please enter token PIN"))
        assertNull(OpenVpnManagement.staticChallenge(">PASSWORD:Need 'Auth' username/password"))
        assertEquals("SCRV1:YmFy:ODY3NTMwOQ==", OpenVpnManagement.staticPassword("bar", "8675309", concatenate = false))
        assertEquals("bar8675309", OpenVpnManagement.staticPassword("bar", "8675309", concatenate = true))
    }
}
