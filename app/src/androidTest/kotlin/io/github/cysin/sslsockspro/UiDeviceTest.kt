package io.github.cysin.sslsockspro

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.cysin.sslsockspro.ui.MainActivity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class UiDeviceTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    private fun tab(name: String) = ui.onNodeWithContentDescription(name, useUnmergedTree = true).performClick()

    @Test fun navigationThemeAndPrivateDraftSurviveRotation() {
        val store = (ui.activity.application as TunnelApplication).profiles
        val original = store.read()
        try {
            ui.waitUntil(10000) { ui.onAllNodesWithText("Your connection").fetchSemanticsNodes().isNotEmpty() }
            tab("Profiles")
            ui.onNodeWithContentDescription("Create profile").assertExists()
            tab("Certificates")
            ui.onNodeWithText("Certificates stay in encrypted private app storage. Private keys are never displayed here.").assertExists()
            tab("Logs")
            ui.onNodeWithText("Connection log").assertExists()
            tab("Settings")
            ui.onNodeWithText("Dark").performClick()
            ui.waitUntil(10000) { store.read().settings.darkTheme == true }
            ui.activityRule.scenario.recreate()
            ui.onNodeWithText("Appearance").assertExists()
            ui.onNodeWithText("Dark").assertIsSelected()

            tab("Profiles")
            ui.onNodeWithContentDescription("Create profile").performClick()
            ui.onNode(hasText("Profile name") and hasSetTextAction()).performTextReplacement("Private rotation draft")
            ui.onNode(hasText("Server IP or hostname") and hasSetTextAction()).performTextReplacement("203.0.113.7")
            ui.activityRule.scenario.recreate()
            ui.onNode(hasText("Profile name") and hasSetTextAction()).assertTextContains("Private rotation draft")
            ui.onNode(hasText("Server IP or hostname") and hasSetTextAction()).assertTextContains("203.0.113.7")
            ui.onNodeWithContentDescription("Cancel editing").performClick()
            assertEquals(original.profiles, store.read().profiles)

            tab("Settings")
            if (original.profiles.isNotEmpty()) {
                ui.onNodeWithText("Create encrypted local backup").performClick()
                ui.onNode(hasText("Backup password") and hasSetTextAction()).performTextInput("temporary-test-password")
                ui.activityRule.scenario.recreate()
                ui.onNodeWithText("Encrypt backup").assertExists()
                ui.onNodeWithText("Encrypt and save").assertIsEnabled()
                ui.onNodeWithText("Cancel").performClick()
            }
            tab("Connection")
            ui.onNodeWithText("Your connection").assertExists()
        } finally { store.write(original) }
    }
}
